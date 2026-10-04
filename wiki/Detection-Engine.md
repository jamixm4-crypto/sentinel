# Устройство движка детекции (Detection Engine)

Движок детекции Sentinel построен на модульной архитектуре коллекторов, объединённых общим трейтом `Collector` в крейте `sentinel-collectors`.

---

## 1. Концепция сбора улик (Evidence Collection)

Каждый запуск сканера формирует снимок текущего состояния системы по нескольким независимым векторам:
1. **Процессы**: список запущенных бинарников, пути к `.exe`, аргументы командной строки.
2. **Персистентность (Автозапуск)**: механизмы, гарантирующие перезапуск софта после ребута.
3. **Аппаратные датчики и API**: свидетельства обращения к камере, микрофону, экрану и клавиатуре.
4. **Сетевые интерфейсы**: прослушиваемые порты и активные подключения.
5. **Системные модификации**: переопределение прокси, сертификаты MITM, правки файла hosts.

---

## 2. Реализация под Windows

### 2.1. Реестр автозагрузки
Коллектор `WindowsPersistenceCollector` проверяет как стандартные ветки, так и 32-битные ветки WOW6432Node:
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` и `RunOnce`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` и `RunOnce`
- Каталог автозагрузки профиля: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- Планировщик задач: перечисление задач через `schtasks.exe /query /fo CSV`

### 2.2. CapabilityAccessManager ConsentStore
Начиная с Windows 10, подсистема `CapabilityAccessManager` фиксирует каждое обращение классических и UWP-приложений к веб-камере, микрофону и захвату экрана:
- Путь реестра: `HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\<capability>\NonPackaged`
- Значения:
  - `LastUsedTimeStart` (FILETIME метка начала использования)
  - `LastUsedTimeStop` (FILETIME метка завершения использования)
- **Признак активной слежки прямо сейчас**: Если `LastUsedTimeStart > 0`, а `LastUsedTimeStop == 0` (или `Start > Stop`), программа в данный момент осуществляет запись экрана или захват видео с камеры.

### 2.3. Клавиатурные фильтр-драйверы
Кейлоггеры уровня ядра регистрируют себя как фильтр-драйверы класса клавиатур:
- Ветка реестра: `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}`
- Ключи `UpperFilters` и `LowerFilters`.
- В штатной системе Windows легитимным значением является только `kbdclass` (и `vmmouse` в виртуалках VMware). Любые сторонние драйверы немедленно помечаются как критическая аномалия.

### 2.4. Скрытые установленные программы
Шпионские утилиты часто скрывают свою запись из апплета «Установка и удаление программ» Windows:
- Ветка: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
- Флаг `SystemComponent = 1` скрывает программу из графического интерфейса Windows Settings.
- Коллектор `WindowsInstalledSoftwareCollector` считывает реестр напрямую, выявляя скрытые записи с параметрами `DisplayName` и `UninstallString`.

### 2.5. Сетевой перехват и MITM-сертификаты
- Проверка системного прокси: `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` (`ProxyEnable`, `ProxyServer`, `AutoConfigURL`).
- Проверка файла `C:\Windows\System32\drivers\etc\hosts` на предмет перенаправления доменов обновлений антивирусов в `127.0.0.1`.
- Проверка хранилища корневых доверенных сертификатов на наличие установленных самоподписанных CA (Fiddler, Charles, Teramind CA).

---

## 3. Реализация под Linux

### 3.1. Анализ устройств ввода
- Перечисление символьных устройств `/dev/input/event*`.
- Проверка дескрипторов процессов в `/proc/<PID>/fd/*` на открытые устройства ввода без прав графической сессии.

### 3.2. Wayland и PipeWire ScreenCast
- Запрос состояния узлов PipeWire через утилиту `pw-dump`.
- Если узел имеет медиа-класс `Stream/Input/Video`, в системе активен захват или трансляция экрана через протокол portal.

### 3.3. Сторожевые процессы и ptrace
- Считывание файла `/proc/<PID>/status` для всех запущенных процессов.
- Поле `TracerPid`: ненулевое значение указывает, что процесс находится под непрерывной отладкой/трассировкой другим процессом (характерно для кейлоггеров и anti-tamper сторожей).

### 3.4. Автозагрузка и внедрение библиотек
- Проверка `/etc/ld.so.preload` на наличие принудительно внедряемых библиотек перехвата libc.
- Пользовательские и системные юниты systemd: `~/.config/systemd/user/` и `/etc/systemd/system/`.
- XDG Autostart: `~/.config/autostart/*.desktop`.

---

## 4. Реализация под macOS

### 4.1. Службы Launchd
- Сканирование каталогов LaunchDaemons и LaunchAgents:
  - `/Library/LaunchDaemons/` (системные демоны с правами root)
  - `/Library/LaunchAgents/` (общесистемные агенты сессии)
  - `~/Library/LaunchAgents/` (пользовательские агенты)
- Детекция агрессивных параметров перезапуска: связка `<key>KeepAlive</key><true/>` и `<key>RunAtLoad</key><true/>`.

### 4.2. MDM Configuration Profiles
- Вызов команды `profiles -P` для проверки наличия профилей мобильного управления предприятием (Jamf, Kandji, Mosyle).
- Выявление установленных сертификатов профиля, разрешающих удалённое администрирование устройства.
