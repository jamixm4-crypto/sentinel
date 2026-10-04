use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lang {
    En,
    Ru,
}

impl Default for Lang {
    fn default() -> Self {
        Self::En
    }
}

impl Lang {
    pub fn from_code(code: &str) -> Self {
        if code.eq_ignore_ascii_case("ru") {
            Self::Ru
        } else {
            Self::En
        }
    }
}

/// Translate a key into the given language
pub fn t(key: &'static str, lang: Lang) -> &'static str {
    match (key, lang) {
        // App metadata
        ("app_title", Lang::En) => "Sentinel — Spyware & Stalkerware Detector",
        ("app_title", Lang::Ru) => "Sentinel — Детектор следящего ПО и сталкерваре",
        ("app_subtitle", Lang::En) => "Defensive, privacy-respecting system audit",
        ("app_subtitle", Lang::Ru) => "Защитный аудит системы без следов и телеметрии",

        // Verdicts
        ("verdict_clean", Lang::En) => "No Surveillance Software Detected",
        ("verdict_clean", Lang::Ru) => "Признаков следящего ПО не обнаружено",
        ("verdict_clean_desc", Lang::En) => "The scan did not find known keyloggers, stalkerware, covert remote access tools, or suspicious process watchers.",
        ("verdict_clean_desc", Lang::Ru) => "Сканирование не выявило известных кейлоггеров, сталкерского ПО, скрытого удалённого доступа или подозрительных сторожевых процессов.",

        ("verdict_review", Lang::En) => "Review Recommended",
        ("verdict_review", Lang::Ru) => "Рекомендуется ручная проверка",
        ("verdict_review_desc", Lang::En) => "Dual-use software, remote access utilities, or activity monitors were found. Verify if you intentionally installed them.",
        ("verdict_review_desc", Lang::Ru) => "Обнаружено ПО двойного назначения (удалённый доступ, учёт времени или родительский контроль). Убедитесь, что вы устанавливали его сами.",

        ("verdict_surveillance", Lang::En) => "Surveillance Software Likely Detected",
        ("verdict_surveillance", Lang::Ru) => "Вероятно обнаружено следящее ПО",
        ("verdict_surveillance_desc", Lang::En) => "Active stalkerware, keyloggers, or unauthorized surveillance software components have been identified on this machine.",
        ("verdict_surveillance_desc", Lang::Ru) => "В системе выявлены компоненты известных программ скрытой слежки, кейлоггеров или нежелательного мониторинга.",

        // Categories
        ("cat_keyboard", Lang::En) => "Keyboard Capture & Keystroke Logging",
        ("cat_keyboard", Lang::Ru) => "Перехват клавиатуры и ввод данных",
        ("cat_screen", Lang::En) => "Screen Capture & Streaming",
        ("cat_screen", Lang::Ru) => "Захват и трансляция экрана",
        ("cat_remote", Lang::En) => "Remote Access & Control",
        ("cat_remote", Lang::Ru) => "Удалённое управление компьютером",
        ("cat_org", Lang::En) => "Organization-Managed Software",
        ("cat_org", Lang::Ru) => "ПО, управляемое организацией",
        ("cat_persistence", Lang::En) => "Suspicious Persistence Hooks",
        ("cat_persistence", Lang::Ru) => "Подозрительная автозагрузка",
        ("cat_network", Lang::En) => "Network Activity & SSL Interception",
        ("cat_network", Lang::Ru) => "Сетевая активность и перехват трафика",
        ("cat_watcher", Lang::En) => "Process Watchers & Anti-Kill",
        ("cat_watcher", Lang::Ru) => "Сторожевые процессы и защита от завершения",

        // Sections
        ("sec_what", Lang::En) => "What is this program?",
        ("sec_what", Lang::Ru) => "Что это за программа?",
        ("sec_why", Lang::En) => "Why was it flagged?",
        ("sec_why", Lang::Ru) => "Почему это попало в отчёт?",
        ("sec_legitimacy", Lang::En) => "Is it likely legitimate?",
        ("sec_legitimacy", Lang::Ru) => "Вероятно ли это легитимная программа?",
        ("sec_remedy", Lang::En) => "How to remediate or remove",
        ("sec_remedy", Lang::Ru) => "Как обезвредить или удалить",
        ("sec_manual_steps", Lang::En) => "Step-by-step manual removal guide",
        ("sec_manual_steps", Lang::Ru) => "Пошаговая инструкция по ручному удалению",

        // Buttons & Actions
        ("btn_quarantine", Lang::En) => "Quarantine (Reversible)",
        ("btn_quarantine", Lang::Ru) => "В карантин (обратимо)",
        ("btn_remove", Lang::En) => "Permanently Remove",
        ("btn_remove", Lang::Ru) => "Удалить полностью",
        ("badge_org_managed", Lang::En) => "Managed by IT — Do Not Auto-Remove",
        ("badge_org_managed", Lang::Ru) => "Управляется вашей организацией — автоудаление заблокировано",

        // Safety warning
        ("safety_warning_title", Lang::En) => "Suspecting surveillance by someone you know?",
        ("safety_warning_title", Lang::Ru) => "Подозреваете слежку со стороны конкретного человека?",
        ("safety_warning_body", Lang::En) => "Warning: Abruptly removing or disabling stalkerware may alert the person monitoring you. Consider creating a safety plan first using an unmonitored device. Resources: stopstalkerware.org | National DV Hotline: 1-800-799-7233 | Europe: lila.help",
        ("safety_warning_body", Lang::Ru) => "Внимание: Внезапное удаление сталкерского ПО может насторожить преследователя. Составьте план безопасности с другого, чистого устройства перед удалением. Ресурсы: stopstalkerware.org | lila.help | Горячие линии кризисной помощи",

        // Limitations
        ("limitations_title", Lang::En) => "Technical Limitations & Transparency",
        ("limitations_title", Lang::Ru) => "Технические ограничения и честность",
        ("limitations_body", Lang::En) => "User-mode scanners cannot reliably detect hardware keyloggers, UEFI/firmware implants, or kernel rootkits already controlling the OS. For maximum confidence, physically inspect keyboard cables or perform an offline scan from a trusted live USB.",
        ("limitations_body", Lang::Ru) => "Сканирование из пользовательского режима не может выявить аппаратные кейлоггеры (переходники на USB), прошивочные закладки или руткиты уровня ядра. Осмотрите физическое подключение клавиатуры или проведите аудит с доверенного загрузочного носителя.",

        // Fallback
        _ => key,
    }
}
