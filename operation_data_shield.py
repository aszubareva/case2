import re
import base64
import codecs


def check_luhn(card_number):
    """
    Проверяет номер карты по алгоритму Луна.
    """
    digits = [int(d) for d in str(card_number) if d.isdigit()]
    digits.reverse()
    total_sum = 0

    for i, digit in enumerate(digits):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9

        total_sum += digit

    return total_sum % 10 == 0


def find_and_validate_credit_cards(text):
    """
    Ищет номера банковских карт
    Возвращает: список найденных номеров банковских карт
    """

    result = {
        'valid': [],
        'invalid': []
    }
    cards = re.findall(r'\b\d{4}[^\d\wа-яА-Я]*\d{4}[^\d\wа-яА-Я]*\d{4}[^\d\wа-яА-Я]*\d{4}\b', text)

    for card in cards:
        if check_luhn(card):
            result['valid'].append(card)
        else:
            result['invalid'].append(card)

    return result


def find_secrets(text):
    """
    Ищет API-ключи, пароли, токены доступа
    Возвращает: список найденных секретов
    """
    # Ищем: sk_live_..., pk_test_..., пароли со спецсимволами

    secrets = {'api_keys': set(), 'passwords': set()}

    match_sk = re.findall(r'sk_live_[A-Za-z0-9]+', text)
    for element in match_sk:
        secrets['api_keys'].add(element)

    match_pk = re.findall(r'pk_test_[A-Za-z0-9]+', text)
    for element in match_pk:
        secrets['api_keys'].add(element)

    match_password = re.findall(r'[A-Za-z0-9!@#$%&*_]{12,}', text)

    for element in match_password:
        if element not in secrets['api_keys'] and \
                not element.startswith('0x') and \
                not element.endswith('='):
            count = 0
            if re.search(r'[A-Z]', element):
                count += 1
            if re.search(r'[a-z]', element):
                count += 1
            if re.search(r'\d', element):
                count += 1
            if re.search(r'[!@#$%&*_]', element):
                count += 1
            if count >= 3:
                secrets['passwords'].add(element)
    return secrets


def find_system_info(text):
    pass


def decode_messages(text):
    """
    Находит и расшифровывает сообщения
    Возвращает: {'base64': [], 'hex': [], 'rot13': []}
    """

    decoded_messages = {'base64': [],
                        'hex': [],
                        'rot13': []}

    # ищем base64
    encoded_base64 = re.findall(r'[A-Za-z0-9+/]{2,}={1,2}', text)
    for element in encoded_base64:

        try:
            decoded_bytes = base64.b64decode(element)
            decoded_element = decoded_bytes.decode('utf-8')
            # содержит буквы, цифры, знаки препинания и пробелы
            if decoded_element.isprintable():
                decoded_messages['base64'].append(decoded_element)

        # не соответсвует формату base64 или
        # не являются валидной UTF‑8 последовательностью

        except (ValueError, UnicodeDecodeError):
            pass


    # ищем формат hex: 0x
    encoded_hex = re.findall(r'0x[A-Fa-f0-9]+', text)
    for element in encoded_hex:
        try:
            decoded_element = codecs.decode(element[2:], 'hex').decode('utf-8')

            # содержит буквы, цифры, знаки препинания и пробелы
            if decoded_element.isprintable():
                decoded_messages['hex'].append(decoded_element)

        # не соответсвует формату hex или
        # не является валидной UTF‑8 последовательностью

        except (ValueError, UnicodeDecodeError):
            pass

    # ищем формат hex: \x..\x..
    encoded_hex = re.findall(r'(?:\\x[A-Fa-f0-9]{2})+', text)
    for element in encoded_hex:
        clean = re.sub(r'\\x', '', element)
        try:
            decoded_element = codecs.decode(clean, 'hex').decode('utf-8')

            # содержит буквы, цифры, знаки препинания и пробелы
            if decoded_element.isprintable():
                decoded_messages['hex'].append(decoded_element)

        # не соответсвует формату hex или
        # не является валидной UTF‑8 последовательностью

        except (ValueError, UnicodeDecodeError):
            pass


    #ищем формат rot13
    encoded_rot13 = re.findall(r'[A-Za-z0-9. !?,]{4,}', text)

    trigger_words = ['password', 'the', 'is', 'secret', 'key',
                     'system', 'message', 'access', 'user',
                     'file', 'code', 'hello', 'and', 'but',
                     'are', 'error', 'flag', 'name', 'that']

    for element in encoded_rot13:
        try:
            decoded_element = codecs.decode(element, 'rot13')
            decoded_lower = decoded_element.lower()
            # если хотя бы 1 слово из триггерных есть
            if any(word in decoded_lower for word in trigger_words):
                decoded_messages['rot13'].append(decoded_element)
        except Exception:
            pass

    return decoded_messages


def analyze_logs(text):
    pass


def normalize_and_validate(data):
    pass


def generate_comprehensive_report(main_text, log_text, messy_data):
    """ Генерирует полный отчет о расследовании """
    report = {'financial_data': find_and_validate_credit_cards(main_text),
              'secrets': find_secrets(main_text),
              'system_info': find_system_info(main_text),
              'encoded_messages': decode_messages(main_text),
              'security_threats': analyze_logs(log_text),
              'normalized_data': normalize_and_validate(messy_data)
              }
    return report


def print_report(report):
    """Красиво выводит отчет"""
    print("=" * 50)
    print("ОТЧЕТ ОПЕРАЦИИ 'DATA SHIELD'")
    print("=" * 50)
    # Вывод результатов каждой роли
    sections = [("ФИНАНСОВЫЕ ДАННЫЕ", report['financial_data']),
                ("СЕКРЕТНЫЕ КЛЮЧИ", report['secrets']),
                ("СИСТЕМНАЯ ИНФОРМАЦИЯ", report['system_info']),
                ("РАСШИФРОВАННЫЕ СООБЩЕНИЯ", report['encoded_messages']),
                ("УГРОЗЫ БЕЗОПАСНОСТИ", report['security_threats']),
                ("НОРМАЛИЗОВАННЫЕ ДАННЫЕ", report['normalized_data'])]
    for title, data in sections:
        print(f"\n{title}:")
        print("-" * 30)
        # Детальный вывод данных...


if __name__ == "__main__":
    # Чтение файлов с данными
    with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
        main_text = f.read()
        print(find_and_validate_credit_cards(main_text))
    with open('web_server_logs.txt', 'r', encoding='utf-8') as f:
        log_text = f.read()
    with open('messy_data.txt', 'r', encoding='utf-8') as f:
        messy_data = f.read()
        # Запуск расследования
        report = generate_comprehensive_report(main_text, log_text, messy_data)
        print_report(report)
