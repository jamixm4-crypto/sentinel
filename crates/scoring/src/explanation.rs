use sentinel_core::{FindingExplanation, Lang, RemovalPolicy};
use sentinel_rules::schema::Rule;

pub fn generate_explanation(rule: &Rule, lang: Lang) -> FindingExplanation {
    match lang {
        Lang::Ru => {
            let (risk, guidance) = match rule.removal_policy {
                RemovalPolicy::DoNotRemove => (
                    "РИСК НАРУШЕНИЯ РЕГЛАМЕНТА: Программа управляется вашей компанией или учебным заведением.".to_string(),
                    "Самостоятельное удаление может заблокировать доступ к корпоративной сети или вызвать служебную проверку. Обратитесь в ваш ИТ-отдел.".to_string(),
                ),
                RemovalPolicy::ManualReview => (
                    "УМЕРЕННЫЙ РИСК: Инструмент двойного назначения (удаленное управление, телеметрия, мониторинг).".to_string(),
                    "Проверьте историю установки. Если вы не устанавливали эту программу — возможно, устройство скомпрометировано. Перед удалением зафиксируйте доказательства.".to_string(),
                ),
                RemovalPolicy::SafeAuto => (
                    "КРИТИЧЕСКИЙ РИСК ДЛЯ ЛИЧНОЙ БЕЗОПАСНОСТИ: Удаление программы может отправить преследователю тревожное уведомление ('Устройство не на связи'), что может спровоцировать агрессию.".to_string(),
                    "1. НЕ удаляйте программу прямо сейчас, если живёте с преследователем.\n2. Свяжитесь со службой поддержки с другого, чистого устройства.\n3. Справочник кризисных центров: https://lila.help | Coalition Against Stalkerware: https://stopstalkerware.org\n4. Горячие линии: Центр «Анна» 8-800-7000-600 | «Насилию.нет» +7 (495) 916-30-00.".to_string(),
                ),
            };

            FindingExplanation {
                what_is_it: rule.description.clone(),
                why_flagged: format!(
                    "Обнаружены признаки: имя процесса, путь автозапуска или системная служба, соответствующие сигнатуре '{}'.",
                    rule.name
                ),
                is_legitimate: if rule.is_legitimate_use_likely {
                    "Вероятно легитимное ПО. Если вы устанавливали эту программу сами, причин для беспокойства нет.".to_string()
                } else {
                    "Маловероятно. Данное ПО ориентировано на скрытое наблюдение без ведома пользователя.".to_string()
                },
                recommendation: match rule.removal_policy {
                    RemovalPolicy::DoNotRemove => {
                        "Это корпоративное ПО, управляемое вашей организацией. Не пытайтесь удалить его самостоятельно, обратитесь в ИТ-отдел.".to_string()
                    }
                    RemovalPolicy::ManualReview => {
                        "Проверьте, знакома ли вам эта программа. Если нет — используйте функцию карантина или удалите её.".to_string()
                    }
                    RemovalPolicy::SafeAuto => {
                        "Рекомендуется поместить в карантин или удалить. Если подозреваете слежку от близкого человека, сначала подготовьте план безопасности.".to_string()
                    }
                },
                safety_risk: Some(risk),
                emergency_guidance: Some(guidance),
            }
        }
        Lang::En => {
            let (risk, guidance) = match rule.removal_policy {
                RemovalPolicy::DoNotRemove => (
                    "ORGANIZATIONAL POLICY RISK: Software is centrally managed by your employer or school.".to_string(),
                    "Tampering with this software may revoke corporate access or breach IT security policies. Contact your system administrator.".to_string(),
                ),
                RemovalPolicy::ManualReview => (
                    "MODERATE RISK: Dual-use administrative or remote assistance utility.".to_string(),
                    "Verify if you or an authorized technician installed this. If unprompted, preserve forensic logs before taking action.".to_string(),
                ),
                RemovalPolicy::SafeAuto => (
                    "HIGH PERSONAL SAFETY RISK: Deleting or killing this software may immediately notify the abuser that surveillance has stopped, which could trigger escalation.".to_string(),
                    "1. Do NOT delete this tool right now if you are in physical proximity to the abuser.\n2. Contact a confidential crisis organization from a clean/external device.\n3. Worldwide resources directory: https://lila.help | Coalition: https://stopstalkerware.org\n4. US National Domestic Violence Hotline: 1-800-799-SAFE (or text 'START' to 88788) | UK: 0808 2000 247.".to_string(),
                ),
            };

            FindingExplanation {
                what_is_it: rule.description.clone(),
                why_flagged: format!(
                    "Identified matching process, persistence hook, or service signature for '{}'.",
                    rule.name
                ),
                is_legitimate: if rule.is_legitimate_use_likely {
                    "Likely legitimate. If you installed this software yourself, no action is needed.".to_string()
                } else {
                    "Unlikely to be legitimate. This software is designed for covert surveillance without clear user consent.".to_string()
                },
                recommendation: match rule.removal_policy {
                    RemovalPolicy::DoNotRemove => {
                        "This software is managed by your organization. Do not attempt removal; contact your IT department.".to_string()
                    }
                    RemovalPolicy::ManualReview => {
                        "Verify whether you recognize this program. If unexpected, quarantine or remove it.".to_string()
                    }
                    RemovalPolicy::SafeAuto => {
                        "Recommended for quarantine or removal. If you suspect domestic abuse, ensure you have a safety plan first.".to_string()
                    }
                },
                safety_risk: Some(risk),
                emergency_guidance: Some(guidance),
            }
        }
    }
}
