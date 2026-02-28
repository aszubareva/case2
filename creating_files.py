content_leak = """
Конфиденциальные данные:
Карты: 4532-4512-8795-2109, 4111 1111 1111 1111, 0000-0000
API-ключи: sk_live_51Mn8cB7xY9zA1b2C3d4E5f6G7h8I9j0K, pk_test_123abc
Пароли: like_This_123!, Summer2024!
IP-адреса: 192.168.1.1, 10.0.0.255
Email: alice.wonderland@securecorp.com
Base64: VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIQ==
Hex: 0x4D7950617373
ROT13: Gur cnffjbeq vf Summer2024!
"""

content_logs = """
192.168.1.100 - "GET /search?q=<script>alert('xss')</script>"
203.0.113.5 - "GET /admin" 401 "EvilBot/1.0"
10.0.0.50 - "GET /products?id=1' OR '1'='1"
192.168.1.1 - "GET /home" 200
"""

content_messy = """
Телефоны: 8-912-345-67-89, +79123456789, 8999000
Даты: 15.02.2024, 2024/02/15, 99.99.2024
ИНН: 1234567890, 123456789012, 123
Карты: 4532-4512-8795-2109
"""

with open('data_leak_sample.txt', 'w', encoding='utf-8') as f:
    f.write(content_leak)
with open('web_server_logs.txt', 'w', encoding='utf-8') as f:
    f.write(content_logs)
with open('messy_data.txt', 'w', encoding='utf-8') as f:
    f.write(content_messy)
