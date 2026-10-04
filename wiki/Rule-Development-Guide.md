# Руководство по разработке и тестированию правил

База правил Sentinel построена на декларативных YAML-файлах. Каждое правило описывает признаки конкретного ПО (процессы, ключи автозапуска, файлы, сетевые порты, сторожевые процессы) и определяет политику реагирования.

Правила компилируются непосредственно в бинарный файл Sentinel при сборке (`crates/rules/src/lib.rs`), а также могут загружаться динамически из внешнего каталога с помощью ключа `--rules-dir <path>`.

---

## Структура YAML-правила

Каждое правило должно строго следовать следующей схеме:

```yaml
id: unique_snake_case_identifier
name: "Человекочитаемое название ПО"
description: "Подробное описание назначения программы, её возможностей и рисков."
category: stalkerware | corporate | remote_access | edr_mdm | legitimate
threat_level: critical | high | medium | low | info
confidence: 0.95 # Значение от 0.0 до 1.0 (95% уверенность)
platforms:
  - windows
  - linux
  - macos
removal_policy: safe_auto | manual_review | do_not_remove

conditions:
  processes:
    - name: "target.exe"
      command_line_contains: "--hidden"
      min_count: 1
  autorun:
    - path_contains: "TargetApp"
      registry_key_contains: "CurrentVersion\\Run"
      type: "registry" # registry | scheduled_task | systemd | launch_daemon | launch_agent
  network:
    - local_ports: [4444, 5555]
      remote_ips: []
      dns_domains: ["api.stalkerapp.com"]
      established_only: true
  files:
    - path_glob: "C:\\ProgramData\\TargetApp\\*.exe"
      hash_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      signature_signer: ""
      min_size: 1024
      max_size: 10485760
  watchdog:
    parent_process: "watchdog.exe"
    restarts_child: true
    hides_window: true

removal:
  kill_watchdogs:
    - "watchdog.exe"
  stop_services:
    - "TargetSvc"
  kill_processes:
    - "target.exe"
  disable_autorun:
    - "TargetAppRun"
  quarantine_files:
    - "C:\\ProgramData\\TargetApp"
  backup_registry:
    - "HKLM\\Software\\TargetApp"
```

---

## Описание полей

### 1. Метаданные

| Поле | Тип | Обязательное | Описание |
| :--- | :--- | :--- | :--- |
| `id` | String | Да | Уникальный буквенно-цифровой идентификатор в `snake_case` (например, `mspy_windows`, `anydesk_remote`). |
| `name` | String | Да | Официальное или общепринятое название программного обеспечения. |
| `description` | String | Да | Описание функционала: ведёт ли запись нажатий, скрывает ли окно, передаёт ли скриншоты. |
| `category` | Enum | Да | Категория ПО (см. таблицу категорий ниже). |
| `threat_level` | Enum | Да | Уровень угрозы: `critical`, `high`, `medium`, `low`, `info`. |
| `confidence` | Float | Да | Базовая достоверность совпадения от `0.0` до `1.0`. Если совпали несколько разнородных артефактов (процесс + ключ реестра + файл), движок динамически повышает скор. |
| `platforms` | List | Да | Поддерживаемые ОС: `windows`, `linux`, `macos`. |
| `removal_policy` | Enum | Да | Политика деинсталляции/карантина (см. таблицу политик). |

---

## Категории (`category`)

1. **`stalkerware`**: Специализированное шпионское ПО, предназначенное для скрытой слежки за партнёрами, родственниками или детьми без их ведома. Скрывает интерфейс, маскируется под системные службы, перехватывает ввод, делает снимки экрана.
2. **`corporate`**: Системы учёта рабочего времени и мониторинга сотрудников (StaffCop, Kickidler, Hubstaff, Teramind). Часто устанавливаются работодателями легитимно, но могут собирать избыточные данные.
3. **`remote_access`**: Утилиты удалённого администрирования и экрана (AnyDesk, TeamViewer, RustDesk, VNC, RDP). Софт двойного назначения: может использоваться легитимно или злоумышленниками для негласного доступа.
4. **`edr_mdm`**: Корпоративные агенты безопасности и управления парком устройств (CrowdStrike Falcon, Microsoft Defender ATP, SentinelOne, Jamf Pro).
5. **`legitimate`**: Легитимные программы, обладающие схожими механизмами (OBS Studio, Discord Screen Share, специализированные службы специальных возможностей). Используются для исключения ложных срабатываний.

---

## Политики удаления (`removal_policy`)

| Политика | Назначение | Поведение в CLI |
| :--- | :--- | :--- |
| `safe_auto` | Однозначно нежелательное или шпионское ПО (кейлоггеры, stalkerware). | Разрешено к изоляции через `quarantine` и пакетному удалению `remove --all-safe`. |
| `manual_review` | Программы двойного назначения (Remote Access, рекордеры, трекеры). | Требует отдельного интерактивного подтверждения на каждый компонент. Пакетное удаление заблокировано. |
| `do_not_remove` | Корпоративные EDR, системные компоненты, MDM. | **Заблокировано навсегда**. Удаление сломает корпоративную сеть, вызовет сетевую изоляцию или нарушит трудовой договор. |

---

## Логика сопоставления (`conditions`)

Движок сопоставления использует следующую логику:
- **Между блоками условий** (processes, autorun, network, files) применяется логика **И (AND)** для всех непустых блоков.
- **Внутри списков** каждого блока применяется логика **ИЛИ (OR)** — совпадение хотя бы одного элемента списка удовлетворяет блоку.
- **Внутри объекта правила** все указанные атрибуты должны совпасть одновременно (например, имя процесса `target.exe` И подстрока в аргументах `--hidden`).

### Пример правила для шпионской утилиты

```yaml
id: real_spy_monitor
name: "Real Spy Monitor"
description: "Коммерческий кейлоггер и инструмент негласного мониторинга клавиатуры и веб-камеры."
category: stalkerware
threat_level: critical
confidence: 0.95
platforms:
  - windows
removal_policy: safe_auto

conditions:
  processes:
    - name: "rsm.exe"
    - name: "rsmsvc.exe"
  autorun:
    - path_contains: "Real Spy Monitor"
    - registry_key_contains: "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  files:
    - path_glob: "C:\\Program Files*\\Real Spy Monitor\\*.exe"

removal:
  stop_services:
    - "RSMService"
  kill_processes:
    - "rsm.exe"
    - "rsmsvc.exe"
  quarantine_files:
    - "C:\\Program Files (x86)\\Real Spy Monitor"
    - "C:\\ProgramData\\RSM"
```

---

## Валидация и тестирование правил

Перед отправкой Pull Request с новыми правилами выполните локальную валидацию:

```powershell
# Проверка синтаксиса и структуры встроенных или внешних правил
sentinel rules validate --dir ./rules

# Вывод детальной информации о конкретном правиле
sentinel rules explain real_spy_monitor
```

### Автоматический линтинг в CI
В репозитории настроен GitHub Action `.github/workflows/rules-validate.yml`, который автоматически проверяет:
1. Валидность YAML-разметки.
2. Уникальность идентификаторов `id`.
3. Соответствие категорий и уровней угроз допустимым перечислениям.
4. Наличие непустых условий `conditions`.
5. Корректность путей и политик удаления.
