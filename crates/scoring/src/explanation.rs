use sentinel_core::{FindingExplanation, Lang, RemovalPolicy};
use sentinel_rules::schema::Rule;

pub fn generate_explanation(rule: &Rule, lang: Lang) -> FindingExplanation {
    match lang {
        Lang::Ru => FindingExplanation {
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
        },
        Lang::En => FindingExplanation {
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
        },
    }
}
