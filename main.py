import json
import re
import shutil
import socket
import subprocess
from urllib.parse import quote

import pystyle
import dns.resolver
import requests
from colorama import init
from openai import OpenAI


# ============================================================
#                    API CONFIGURATION
# ============================================================

print("\n" + "=" * 60)
print("                 AURORA API CONFIG")
print("=" * 60)

DEEPSEEK_API_KEY = input(
    "\nВведите API нейросети: "
).strip()

DEEPSEEK_MODEL = input(
    "Введите модель нейросети "
    "[Enter = deepseek-v4-flash]: "
).strip()

if not DEEPSEEK_MODEL:
    DEEPSEEK_MODEL = "deepseek-v4-flash"

SEARCH_API_TOKEN = input(
    "Введите API для поиска: "
).strip()

BASE_URL = input(
    "Введите URL API для поиска: "
).strip()

if not DEEPSEEK_API_KEY:
    print("[!] API нейросети не указан.")
    raise SystemExit(1)

if not SEARCH_API_TOKEN:
    print("[!] API поиска не указан.")
    raise SystemExit(1)

if not BASE_URL:
    print("[!] URL API поиска не указан.")
    raise SystemExit(1)

print("\n[+] Конфигурация загружена.")


# ============================================================
#                         COLORAMA
# ============================================================

init(autoreset=True)


# ============================================================
#                      DEEPSEEK CLIENT
# ============================================================

deepseek_client = OpenAI(
    api_key=DEEPSEEK_API_KEY,
    base_url="https://api.deepseek.com"
)


# ============================================================
#                    ОБЩИЕ ФУНКЦИИ
# ============================================================

def normalize_text(value):
    value = str(value).strip()
    value = re.sub(r"\s+", " ", value)
    return value


def json_text(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        default=str
    )


# ============================================================
#                    ОЧИСТКА ОТ СЕКРЕТОВ
# ============================================================

BLOCKED_FIELDS = {
    "password",
    "passwd",
    "pass",
    "token",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
    "privatekey",
    "cookie",
    "session"
}


def clean_data(value):

    if isinstance(value, dict):

        result = {}

        for key, item in value.items():

            normalized = (
                str(key)
                .lower()
                .strip()
                .replace("-", "_")
                .replace(" ", "_")
            )

            if normalized in BLOCKED_FIELDS:
                continue

            result[key] = clean_data(item)

        return result

    if isinstance(value, list):

        return [
            clean_data(item)
            for item in value
        ]

    return value


# ============================================================
#                      SEARCH API
# ============================================================

def api_request(endpoint, query):

    query = normalize_text(query)

    if not query:

        return {
            "error": "Пустой запрос"
        }

    url = (
        f"{BASE_URL.rstrip('/')}/api/"
        f"{quote(SEARCH_API_TOKEN, safe='')}/"
        f"{endpoint}/"
        f"{quote(query, safe='')}"
    )

    try:

        response = requests.get(
            url,
            timeout=20,
            headers={
                "Accept": "application/json",
                "User-Agent": "AURORA/1.0"
            }
        )

        response.raise_for_status()

        return clean_data(
            response.json()
        )

    except requests.exceptions.Timeout:

        return {
            "error": "Search API timeout"
        }

    except requests.exceptions.ConnectionError:

        return {
            "error": "Не удалось подключиться к Search API"
        }

    except requests.exceptions.HTTPError as error:

        status = (
            error.response.status_code
            if error.response is not None
            else "unknown"
        )

        return {
            "error": f"Search API HTTP {status}"
        }

    except requests.exceptions.RequestException as error:

        return {
            "error": f"Search API error: {error}"
        }

    except ValueError:

        return {
            "error": "Search API вернул некорректный JSON"
        }

    except Exception as error:

        return {
            "error": str(error)
        }


def search_api(query):

    return api_request(
        "search",
        query
    )


def extended_search_api(query):

    return api_request(
        "extended_search",
        query
    )


# ============================================================
#                           DNS
# ============================================================

def clean_domain(domain):

    domain = normalize_text(domain)

    domain = re.sub(
        r"^https?://",
        "",
        domain,
        flags=re.IGNORECASE
    )

    domain = domain.split("/")[0]
    domain = domain.split(":")[0]

    return domain.lower()


def dns_lookup(domain):

    domain = clean_domain(domain)

    result = {
        "domain": domain,
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": []
    }

    record_types = [
        ("A", "A"),
        ("AAAA", "AAAA"),
        ("MX", "MX"),
        ("NS", "NS"),
        ("TXT", "TXT")
    ]

    for label, record_type in record_types:

        try:

            answers = dns.resolver.resolve(
                domain,
                record_type,
                lifetime=8
            )

            for answer in answers:

                if record_type == "MX":

                    value = str(
                        answer.exchange
                    ).rstrip(".")

                elif record_type == "TXT":

                    value = str(answer)

                else:

                    value = str(answer)

                result[label].append(
                    value
                )

        except Exception:
            pass

    return result


# ============================================================
#                            IP
# ============================================================

def ip_lookup(target):

    target = clean_domain(target)

    try:

        hostname, aliases, addresses = (
            socket.gethostbyname_ex(target)
        )

        return {
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses
        }

    except Exception as error:

        return {
            "error": str(error)
        }


# ============================================================
#                           RDAP
# ============================================================

def rdap_lookup(domain):

    domain = clean_domain(domain)

    try:

        response = requests.get(
            f"https://rdap.org/domain/"
            f"{quote(domain, safe='')}",
            timeout=15,
            headers={
                "Accept": "application/rdap+json"
            }
        )

        response.raise_for_status()

        data = response.json()

        return clean_data({
            "ldhName": data.get("ldhName"),
            "handle": data.get("handle"),
            "status": data.get("status"),
            "events": data.get("events"),
            "nameservers": [
                ns.get("ldhName")
                for ns in data.get(
                    "nameservers",
                    []
                )
                if isinstance(ns, dict)
                and ns.get("ldhName")
            ]
        })

    except requests.exceptions.RequestException as error:

        return {
            "error": f"RDAP error: {error}"
        }

    except ValueError:

        return {
            "error": "RDAP вернул некорректный JSON"
        }

    except Exception as error:

        return {
            "error": str(error)
        }


# ============================================================
#                         SHERLOCK
# ============================================================

def sherlock_lookup(username):

    username = normalize_text(
        username
    ).lstrip("@")

    if not username:

        return {
            "error": "Пустой username"
        }

    sherlock_path = shutil.which(
        "sherlock"
    )

    if not sherlock_path:

        return {
            "error": (
                "Sherlock не найден. "
                "Установи: pip install sherlock-project"
            )
        }

    try:

        process = subprocess.run(
            [
                sherlock_path,
                username,
                "--print-found",
                "--no-color"
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

        return {
            "username": username,
            "exit_code": process.returncode,
            "found": process.stdout.strip(),
            "errors": process.stderr.strip()
        }

    except subprocess.TimeoutExpired:

        return {
            "error": "Sherlock превысил 180 секунд"
        }

    except Exception as error:

        return {
            "error": str(error)
        }


# ============================================================
#                  GOOGLE DORK GENERATOR
# ============================================================

def generate_google_dorks(query):

    query = normalize_text(query)

    if not query:

        return {
            "error": "Пустой запрос"
        }

    escaped = query.replace(
        '"',
        '\\"'
    )

    return {
        "target": query,
        "queries": [
            f'"{escaped}"',
            f'"{escaped}" filetype:pdf',
            f'"{escaped}" filetype:doc',
            f'"{escaped}" filetype:docx',
            f'"{escaped}" filetype:xls',
            f'"{escaped}" filetype:xlsx',
            f'"{escaped}" after:2025/01/01',
            f'"{escaped}" before:2027/01/01'
        ]
    }


# ============================================================
#                   GOOGLE DORK PARSER
# ============================================================

def parse_google_dork(dork):

    dork = normalize_text(dork)

    if not dork:

        return {
            "error": "Пустой Dork"
        }

    result = {
        "original": dork,
        "phrases": [],
        "operators": [],
        "excluded": [],
        "plain_terms": [],
        "google_url": (
            "https://www.google.com/search?q="
            + quote(dork, safe="")
        )
    }

    # Exact phrases

    phrases = re.findall(
        r'"([^"]*)"',
        dork
    )

    result["phrases"] = [
        phrase
        for phrase in phrases
        if phrase.strip()
    ]

    # Site

    sites = re.findall(
        r'(?<!\S)site:([^\s]+)',
        dork,
        flags=re.IGNORECASE
    )

    for site in sites:

        result["operators"].append({
            "type": "site",
            "value": site
        })

    # Filetype

    filetypes = re.findall(
        r'(?<!\S)filetype:([A-Za-z0-9]+)',
        dork,
        flags=re.IGNORECASE
    )

    for filetype in filetypes:

        result["operators"].append({
            "type": "filetype",
            "value": filetype.lower()
        })

    # After

    after_dates = re.findall(
        r'(?<!\S)after:'
        r'([0-9]{4}[/-][0-9]{1,2}[/-][0-9]{1,2})',
        dork,
        flags=re.IGNORECASE
    )

    for date in after_dates:

        result["operators"].append({
            "type": "after",
            "value": date
        })

    # Before

    before_dates = re.findall(
        r'(?<!\S)before:'
        r'([0-9]{4}[/-][0-9]{1,2}[/-][0-9]{1,2})',
        dork,
        flags=re.IGNORECASE
    )

    for date in before_dates:

        result["operators"].append({
            "type": "before",
            "value": date
        })

    # Excluded terms

    excluded = re.findall(
        r'(?<!\S)-([^\s]+)',
        dork
    )

    result["excluded"] = excluded

    for item in excluded:

        result["operators"].append({
            "type": "exclude",
            "value": item
        })

    # Plain terms

    plain = re.sub(
        r'"[^"]*"',
        "",
        dork
    )

    plain = re.sub(
        r'(?<!\S)'
        r'(site|filetype|after|before):[^\s]+',
        "",
        plain,
        flags=re.IGNORECASE
    )

    plain = re.sub(
        r'(?<!\S)-[^\s]+',
        "",
        plain
    )

    result["plain_terms"] = [
        item
        for item in plain.split()
        if item
    ]

    return result


# ============================================================
#                           TOOLS
# ============================================================

TOOLS = [

    {
        "type": "function",
        "function": {
            "name": "search_api",
            "description": (
                "Обычный поиск по Search API."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string"
                    }
                },
                "required": ["query"],
                "additionalProperties": False
            }
        }
    },

    {
        "type": "function",
        "function": {
            "name": "extended_search_api",
            "description": (
                "Расширенный поиск по Search API."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string"
                    }
                },
                "required": ["query"],
                "additionalProperties": False
            }
        }
    },

    {
        "type": "function",
        "function": {
            "name": "dns_lookup",
            "description": (
                "Получает публичные DNS-записи домена."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string"
                    }
                },
                "required": ["domain"],
                "additionalProperties": False
            }
        }
    },

    {
        "type": "function",
        "function": {
            "name": "ip_lookup",
            "description": (
                "Получает IP-адреса доменного имени."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string"
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            }
        }
    },

    {
        "type": "function",
        "function": {
            "name": "rdap_lookup",
            "description": (
                "Получает публичные регистрационные "
                "данные домена через RDAP."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string"
                    }
                },
                "required": ["domain"],
                "additionalProperties": False
            }
        }
    },

    {
        "type": "function",
        "function": {
            "name": "sherlock_lookup",
            "description": (
                "Проверяет username по публичным "
                "сайтам через Sherlock."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string"
                    }
                },
                "required": ["username"],
                "additionalProperties": False
            }
        }
    },

    {
        "type": "function",
        "function": {
            "name": "generate_google_dorks",
            "description": (
                "Генерирует Google Dorks для "
                "публичного поиска."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string"
                    }
                },
                "required": ["query"],
                "additionalProperties": False
            }
        }
    },

    {
        "type": "function",
        "function": {
            "name": "parse_google_dork",
            "description": (
                "Разбирает существующий Google Dork "
                "и создаёт ссылку для ручного поиска."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "dork": {
                        "type": "string"
                    }
                },
                "required": ["dork"],
                "additionalProperties": False
            }
        }
    }
]


# ============================================================
#                      TOOL EXECUTOR
# ============================================================

def execute_tool(name, arguments):

    if name == "search_api":

        return search_api(
            arguments["query"]
        )

    if name == "extended_search_api":

        return extended_search_api(
            arguments["query"]
        )

    if name == "dns_lookup":

        return dns_lookup(
            arguments["domain"]
        )

    if name == "ip_lookup":

        return ip_lookup(
            arguments["target"]
        )

    if name == "rdap_lookup":

        return rdap_lookup(
            arguments["domain"]
        )

    if name == "sherlock_lookup":

        return sherlock_lookup(
            arguments["username"]
        )

    if name == "generate_google_dorks":

        return generate_google_dorks(
            arguments["query"]
        )

    if name == "parse_google_dork":

        return parse_google_dork(
            arguments["dork"]
        )

    return {
        "error": f"Неизвестный инструмент: {name}"
    }


# ============================================================
#                       SYSTEM PROMPT
# ============================================================

SYSTEM_PROMPT = """
Ты — AURORA Personal OSINT.

Твоя задача — проводить структурированный анализ
собственных или разрешённых пользователем данных
и публичных источников.

Доступные инструменты:

- Search API
- Extended Search API
- DNS
- IP lookup
- RDAP
- Sherlock
- Google Dork generator
- Google Dork parser

РАБОТА:

ПРАВИЛО 1. КЛАССИФИКАЦИЯ ЦЕЛИ

Определить один тип:

PERSON
USERNAME
EMAIL
DOMAIN
IP
GENERAL

ПРАВИЛО 2. СОСТАВЛЕНИЕ ПЛАНА

План формируется до любого запроса и содержит:

тип цели,

3–5 ключевых источников,

ожидаемые сущности для кросс-проверки,

лимит времени на этап.

План выводится в начале ответа.

ПРАВИЛО 3. ФИЛЬТР ИНСТРУМЕНТОВ

Использовать только разрешённые инструменты.

Запрещены:

- брутфорс;
- взлом;
- социальная инженерия;
- обход CAPTCHA;
- незаконный доступ.

ПРАВИЛО 4. НЕ ЗАПУСКАТЬ ВСЁ ПОДРЯД

Выполнять не более 3–5 инструментов за один цикл.

ПРАВИЛО 5. DOMAIN

Последовательность:

DNS
IP
RDAP
Search

ПРАВИЛО 6. USERNAME

Последовательность:

Sherlock
выборочная проверка публичных профилей
кросс-проверка

ПРАВИЛО 7. GOOGLE DORK

Перед использованием Google Dork
сгенерировать минимум 3 поисковых запроса.

Не выполнять автоматический перебор страниц.

ПРАВИЛО 8. КРОСС-ПРОВЕРКА

Для важных сущностей желательно использовать
минимум 2 независимых источника.

ПРАВИЛО 9. ПРОТИВОРЕЧИЯ

Использовать формат:

[ПРОТИВОРЕЧИЕ]
Источник А: значение X
Источник Б: значение Y
Причина: ...

ПРАВИЛО 10. ДОСТОВЕРНОСТЬ

[ФАКТ] — подтверждено несколькими источниками.

[ГИПОТЕЗА] — только один источник
или косвенная связь.

[НЕТ ДАННЫХ] — данных нет.

ПРАВИЛО 11. SHERLOCK

Результат Sherlock считать списком кандидатов,
а не окончательным доказательством принадлежности
аккаунта человеку.

ПРАВИЛО 12. ЗАПРЕЩЕННЫЕ ДАННЫЕ

Не извлекать и не выводить:

API-ключи,
токены,
секреты,
private keys,
cookie-сессии,
данные банковских карт,
пароли.

Если такие данные встречаются,
заменять их на:

[СКРЫТО ПО ПРОТОКОЛУ]

ПРАВИЛО 13. НЕ ВЫДУМЫВАТЬ ДАННЫЕ

Если инструмент вернул null,
timeout или error:

[ОТСУТСТВУЕТ]

Не генерировать вымышленные значения.

ФИНАЛЬНЫЙ ОТЧЁТ:

РЕЗУЛЬТАТ

ЦЕЛЬ:
...

ТИП:
...

ПЛАН:
...

НАЙДЕНО:
...

ПРОФИЛИ:
...

EMAIL / DOMAIN:
...

DNS / IP:
...

RDAP:
...

СВЯЗИ:
...

GOOGLE DORKS:
...

ИСТОЧНИКИ:
...

УВЕРЕННОСТЬ:
HIGH / MEDIUM / LOW

ПРИМЕЧАНИЕ:
...
"""


# ============================================================
#                      DEEPSEEK AGENT
# ============================================================

def ask_deepseek(user_query):

    messages = [
        {
            "role": "system",
            "content": SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": user_query
        }
    ]

    max_rounds = 10

    for _ in range(max_rounds):

        response = (
            deepseek_client
            .chat
            .completions
            .create(
                model=DEEPSEEK_MODEL,
                messages=messages,
                tools=TOOLS,
                tool_choice="auto"
            )
        )

        message = response.choices[0].message

        # ----------------------------------------------------
        # Финальный ответ
        # ----------------------------------------------------

        if not message.tool_calls:

            return (
                message.content
                or "Модель не вернула результат."
            )

        # ----------------------------------------------------
        # Сохраняем assistant message
        # ----------------------------------------------------

        tool_calls_for_history = []

        for tool_call in message.tool_calls:

            tool_calls_for_history.append(
                {
                    "id": tool_call.id,
                    "type": "function",
                    "function": {
                        "name": tool_call.function.name,
                        "arguments": tool_call.function.arguments
                    }
                }
            )

        messages.append(
            {
                "role": "assistant",
                "content": message.content or "",
                "tool_calls": tool_calls_for_history
            }
        )

        # ----------------------------------------------------
        # Выполняем инструменты
        # ----------------------------------------------------

        for tool_call in message.tool_calls:

            try:

                arguments = json.loads(
                    tool_call.function.arguments
                )

                result = execute_tool(
                    tool_call.function.name,
                    arguments
                )

            except json.JSONDecodeError:

                result = {
                    "error": (
                        "Некорректный JSON "
                        "аргументов инструмента."
                    )
                }

            except Exception as error:

                result = {
                    "error": str(error)
                }

            # ------------------------------------------------
            # Возвращаем результат tool_call
            # ------------------------------------------------

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json_text(result)
                }
            )

    return (
        "Анализ остановлен: "
        "достигнут лимит шагов."
    )


# ============================================================
#                           AURORA
# ============================================================

def AI_OSINT():

    query = pystyle.Write.Input(
        "Введите ваш запрос: ",
        pystyle.Colors.blue_to_white,
        interval=0
    )

    if not query:
        return

    try:

        pystyle.Write.Print(
            "\n[•] Важно! Поиск не моментален, "
            "пожалуйста ожидайте...\n",
            pystyle.Colors.blue_to_white,
            interval=0
        )

        result = ask_deepseek(
            normalize_text(query)
        )

        pystyle.Write.Print(
            "\nРезультат:\n",
            pystyle.Colors.blue_to_white,
            interval=0
        )

        print(result)

    except KeyboardInterrupt:

        pystyle.Write.Print(
            "\nОстановка.\n",
            pystyle.Colors.blue_to_white,
            interval=0
        )

    except Exception as error:

        pystyle.Write.Print(
            f"\n[ERROR] {error}\n",
            pystyle.Colors.blue_to_white,
            interval=0
        )


# ============================================================
#                            START
# ============================================================

if __name__ == "__main__":
    AI_OSINT()
