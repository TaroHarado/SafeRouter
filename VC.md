# VC.ru draft

## Заголовок

Сервис, который проверяет: можно ли доверять дешёвому AI API для coding-агентов

## Текст

Сейчас всё больше разработчиков покупают дешёвые third-party LLM endpoints — “Claude-compatible”, “GPT-compatible”, “OpenAI API за копейки”.

Но как понять, что под этим не скрывается:

- downgrade модели,
- вредные tool calls,
- попытки читать `.env`,
- небезопасные shell-команды,
- скрытая подмена поведения для coding-агентов?

Я делаю SafeRouter / carapace — локальный продукт, который:

1. прогоняет endpoint через батарею agent-safety probe’ов,
2. оценивает model identity confidence,
3. выдаёт score / badge / signed artifact,
4. позволяет хранить и синхронизировать trust registry.

Формат результата не “красиво/некрасиво”, а рабочий:

- Agent-safe
- Chat-only
- Do not use with auto-approve

То есть это не очередной AI-лендинг, а инструмент проверки доверия к поставщику моделей.

Сейчас всё работает локально, без hosted key storage: SafeRouter UI поднимается на `localhost` и ходит в локальный daemon.

Repo: https://github.com/TaroHarado/carapace
