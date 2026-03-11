import re
import base64
import codecs
import ast

def check_luhn(card_number):
    """
    Проверяет номер карты по алгоритму Луна.
    """
    try:
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

    except (ValueError, TypeError):
        pass

def find_and_validate_credit_cards(text):
    """
    Ищет номера банковских карт
    Возвращает: список найденных номеров банковских карт
    """
    try:
        result = {
            'valid': [],
            'invalid': []
        }
        cards = re.findall(r'\b\d{4}[^\d\wа-яА-Я]*\d{4}[^\d\wа-яА-Я]*\d{4}['
                           r'^\d\wа-яА-Я]*\d{4}\b', text)

        for card in cards:
            if check_luhn(card):
                result['valid'].append(card)
            else:
                result['invalid'].append(card)

        return result

    except (ValueError, TypeError):
        pass

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
    """
    Ищет системную информацию (IP, файлы, email).
    Возвращает: {'ips': [], 'files': [], 'emails': []}
    """

    result = {
        'ips': [],
        'files': [],
        'emails': []
    }

    # Ищем IP-адреса (v4 и v6)
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    ips = re.findall(ipv4_pattern, text)
    ips += re.findall(ipv6_pattern, text)
    result['ips'] = ips

    # Ищем файлы
    ext = (
        r'jpg|png|bmp|gif|tif|doc|docx|xls|xlsx|pdf|txt|zip|rar|7z|'
        r'gzip|mp3|wav|midi|aac|mp4|avi|mkv|wmv|flv|mpeg|html|htm|'
        r'mht|ppt|pptx|mdb|accdb|iso|cdr|torrent|djvu|fb2|epub|mobi|'
        r'psd|exe'
    )
    simple_file_pattern = r'\b[\w\-]+\.(?:' + ext + r')\b'
    path_file_pattern = (
        r'\b[A-Z]:[\\/]+(?:[\w\-]+[\\/]+)*[\w\-]+\.(?:' + ext + r')\b'
    )

    files = re.findall(simple_file_pattern, text)
    files += re.findall(path_file_pattern, text)
    result['files'] = files

    # Ищем emails
    email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    result['emails'] = re.findall(email_pattern, text)

    return result

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

def analyze_logs(log_text: str):
    """
    Анализирует текстовые логи веб-сервера на наличие угроз безопасности.

    Аргументы:
        log_text: Многострочный текст лога

    Возвращает:
        Словарь с четырьмя категориями угроз, каждая содержит
        список подозрительных строк лога.
    """
    
    result = {
        "sql_injections": [],
        "xss_attempts": [],
        "suspicious_user_agents": [],
        "failed_logins": [],
    }

    # Создаем паттерн для обнаружения SQL-инъекций
    SQL_PATTERN = re.compile(
    r"(\bunion\s+select\b|\bor\s+'?1'='?1\b|--|;|\bselect\b)",
    re.IGNORECASE, # обрабатываем и верхний, и нижний регистры 
	)

    # Паттерн для обнаружения XSS-атак
    XSS_PATTERN = re.compile(
    r"(<script\b|javascript:|onerror=|onload=)",
    re.IGNORECASE
	)

    # Паттерн для подозрительных User-Agent
    SUSPICIOUS_UA = re.compile(
    r"(sqlmap|nikto|evilbot|curl|python-requests)",
    re.IGNORECASE,
	)

    # Паттерн для HTTP-статусов, означающих отказ в доступе
    STATUS_PATTERN = re.compile(r"\s(401|403)\s")

    # Паттерн для извлечения User-Agent из строки лога
    UA_PATTERN = re.compile(r'"([^"]+)"\s*$')

    
    for line in log_text.splitlines():

        # Пропускаем пустые строки
        if not line.strip():
            continue
        
        # SQL-инъекции
        if SQL_PATTERN.search(line):
            result["sql_injections"].append(line)

        # XSS-атаки
        if XSS_PATTERN.search(line):
            result["xss_attempts"].append(line)

        # Неудачные попытки входа
        if STATUS_PATTERN.search(line) or "/login" in line or "/admin" in line:
            result["failed_logins"].append(line)

         # Подозрительные User-Agent
        ua_match = UA_PATTERN.search(line)

        # Если User-Agent найден — проверяем его по чёрному списку
        if ua_match and SUSPICIOUS_UA.search(ua_match.group(1)):
            result["suspicious_user_agents"].append(line)

    return result

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
        print(data)
        # Детальный вывод данных...


def report_preparation(report):
    """
    Готовит наш отчет для сравнения с отчетом другой команды.
    :param report:
    :return:
    """

    result = []

    # финансовые данные
    result += report['financial_data']['valid']
    result += report['financial_data']['invalid']

    # секреты
    result += list(report['secrets']['api_keys'])
    result += list(report['secrets']['passwords'])

    # системная информация
    result += report['system_info']['ips']
    result += report['system_info']['files']
    result += report['system_info']['emails']

    # расшифрованные сообщения
    result += report['encoded_messages']['base64']
    result += report['encoded_messages']['hex']
    result += report['encoded_messages']['rot13']

    # угрозы безопаности
    result += report['security_threats']['sql_injections']
    result += report['security_threats']['xss_attempts']
    result += report['security_threats']['suspicious_user_agents']
    result += report['security_threats']['failed_logins']

    return result


def normalize_string(string):
    """
    Убирает лишние слэши, кавычки и пробелы
    """
    string = (
        string.replace("\\\\", "\\")  # нормализуем слэши
        .replace("\\'", "'")  # нормализуем кавычки
        .strip()  # убираем пробелы
    )
    return string


def results_comparison(our_report, report_at):
    """
    Сравнивает результаты нашей и другой команды.
    """

    # Наш отчет
    our_report = report_preparation(our_report)

    # Убираем лишние пробелы, кавычки, слэши, повторяющиеся артефакты
    our_report = set(
        normalize_string(x) for x in our_report)
    report_at = set(normalize_string(x) for x in report_at)

    # Результат сравнения.
    result = {
        'losses': list(our_report-report_at),
        'garbage': list(report_at-our_report)
    }

    return result


if __name__ == "__main__":
    # Чтение файлов с данными
    with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
        main_text = f.read()
    with open('web_server_logs.txt', 'r', encoding='utf-8') as f:
        log_text = f.read()
    with open('messy_data.txt', 'r', encoding='utf-8') as f:
        messy_data = f.read()

        # Запуск расследования
        report = generate_comprehensive_report(main_text, log_text, messy_data)
        print_report(report)

        # Мусор и потери других команд.
        teams = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11]
        for team in teams:
            file_name = f'input{team}.txt'

            # Пока нет инпутов других команд, поэтому сделаем так.
            file_name = 'report_anotherteam'

            # Читаем вывод другой команды.
            with open(file_name, 'r', encoding='utf-8') as f:
                report_anotherteam = f.readlines()

                # Мусор и потери.
                garbage_losses = results_comparison(report, report_anotherteam)
                print(f"Мусор и потери команды {team}.")
                print(garbage_losses)
