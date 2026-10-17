import contextlib
import http.client
import io
import json
import threading
import unittest
from http.server import HTTPServer
from unittest.mock import Mock, patch

from gateway import Gateway, MAX_TEXT, Rejected, make_handler, ollama_chat

ALLOW = '{"decision":"allow","reason_code":"ok"}'
DENY = '{"decision":"block","reason_code":"injection"}'


class GuardTests(unittest.TestCase):
    def rejected(self, responses, message="Spiega git revert", code=None, stage=None):
        call = Mock(side_effect=responses)
        with self.assertRaises(Rejected) as caught:
            Gateway("test", call=call).chat({"message": message})
        if code:
            self.assertEqual(caught.exception.code, code)
        if stage:
            self.assertEqual(caught.exception.stage, stage)
        return call, caught.exception

    def test_allow_checks_both_sides(self):
        call = Mock(side_effect=[ALLOW, "git revert crea un nuovo commit.", ALLOW])
        result = Gateway("main", "guard", call).chat({"message": "Spiega git revert"})
        self.assertEqual(result["status"], "allowed")
        self.assertEqual([c.args[0] for c in call.call_args_list], ["guard", "main", "guard"])

    def test_demo_secret_stops_before_any_model(self):
        call, _ = self.rejected([], "DEMO_SECRET_DO_NOT_SEND", "secret_pattern", "input")
        call.assert_not_called()

    def test_github_token_pattern_stops_before_model(self):
        call, _ = self.rejected([], "ghp_" + "A" * 36, "secret_pattern")
        call.assert_not_called()

    def test_input_denial_does_not_generate(self):
        call, _ = self.rejected([DENY], stage="input")
        self.assertEqual(call.call_count, 1)

    def test_invalid_verdicts_fail_closed(self):
        for raw in ["not JSON", "{}", "[]", '{"decision":"maybe","reason_code":"ok"}',
                    '{"decision":"allow","reason_code":"uncertain"}',
                    '{"decision":"allow","reason_code":"ok","extra":true}',
                    '{"decision":true,"reason_code":"ok"}']:
            with self.subTest(raw=raw):
                _, error = self.rejected([raw], code="guard_unavailable_or_invalid")
                self.assertEqual(error.status, 503)

    def test_guard_timeout_fail_closed(self):
        self.rejected([TimeoutError()], code="guard_unavailable_or_invalid")

    def test_generator_timeout_fail_closed(self):
        self.rejected([ALLOW, TimeoutError()], stage="generation")

    def test_output_denied(self):
        call, _ = self.rejected([ALLOW, "candidate not to release", DENY], stage="output")
        self.assertEqual(call.call_count, 3)

    def test_output_secret_not_sent_to_second_classifier(self):
        call, _ = self.rejected([ALLOW, "DEMO_SECRET_DO_NOT_SEND"],
                                code="secret_pattern", stage="output")
        self.assertEqual(call.call_count, 2)

    def test_output_classifier_failure_fail_closed(self):
        self.rejected([ALLOW, "candidate not to release", "bad verdict"], stage="output")

    def test_oversized_request_before_models(self):
        call, _ = self.rejected([], "x" * (MAX_TEXT + 1), code="text_too_large")
        call.assert_not_called()

    def test_client_cannot_choose_roles_tools_or_model(self):
        call = Mock()
        for extra in ["model", "messages", "tools", "stream"]:
            with self.subTest(extra=extra), self.assertRaises(Rejected):
                Gateway("test", call=call).chat({"message": "hello", extra: "override"})
        call.assert_not_called()

    def test_upstream_is_buffered_and_has_no_tools(self):
        with patch("gateway.http.client.HTTPConnection") as factory:
            connection = factory.return_value
            response = connection.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps({
                "done": True, "done_reason": "stop", "message": {"content": "ok"}
            }).encode()
            self.assertEqual(ollama_chat("test", [{"role": "user", "content": "hello"}]), "ok")
            sent = json.loads(connection.request.call_args.args[2])
            self.assertIs(sent["stream"], False)
            self.assertNotIn("tools", sent)
            factory.assert_called_once_with("127.0.0.1", 11434, timeout=120)

    def test_truncated_generation_is_rejected(self):
        with patch("gateway.http.client.HTTPConnection") as factory:
            response = factory.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b'{"done":true,"done_reason":"length","message":{"content":"partial"}}'
            with self.assertRaises(ValueError):
                ollama_chat("test", [])

    def test_http_never_returns_blocked_candidate_or_logs_it(self):
        candidate = "CANDIDATE_MUST_STAY_PRIVATE"
        gateway = Gateway("test", call=Mock(side_effect=[ALLOW, candidate, DENY]))
        server = HTTPServer(("127.0.0.1", 0), make_handler(gateway))
        log = io.StringIO()
        try:
            with contextlib.redirect_stdout(log):
                thread = threading.Thread(target=server.handle_request)
                thread.start()
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                connection.request("POST", "/chat", json.dumps({"message": "hello"}),
                                   {"Content-Type": "application/json"})
                response = connection.getresponse()
                payload = response.read().decode()
                connection.close()
                thread.join(timeout=5)
            self.assertEqual(response.status, 403)
            self.assertNotIn(candidate, payload)
            self.assertNotIn("answer", json.loads(payload))
            self.assertNotIn(candidate, log.getvalue())
            self.assertEqual(json.loads(payload)["stage"], "output")
        finally:
            server.server_close()


if __name__ == "__main__":
    unittest.main()
