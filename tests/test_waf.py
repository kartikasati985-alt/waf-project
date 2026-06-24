import os
import tempfile
import unittest

from main import create_app


class WAFProjectTests(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.NamedTemporaryFile(delete=False)
        self.db.close()
        self.app = create_app(db_path=self.db.name)
        self.client = self.app.test_client()

    def tearDown(self):
        os.unlink(self.db.name)

    def test_allows_normal_request(self):
        response = self.client.get('/search?q=hello')
        self.assertEqual(response.status_code, 200)

    def test_blocks_sql_injection(self):
        response = self.client.get("/search?q=' OR 1=1 --")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["attack_type"], "sql_injection")

    def test_blocks_xss(self):
        response = self.client.post('/comment', json={"message": "<script>alert(1)</script>"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["attack_type"], "xss")

    def test_blocks_path_traversal(self):
        response = self.client.get('/file?name=../../etc/passwd')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["attack_type"], "path_traversal")

    def test_blocks_command_injection(self):
        response = self.client.get('/run?cmd=ls; cat /etc/passwd')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["attack_type"], "command_injection")

    def test_dashboard_available(self):
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'WAF Dashboard', response.data)


if __name__ == '__main__':
    unittest.main()
