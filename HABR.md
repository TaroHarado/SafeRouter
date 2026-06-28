# Habr draft

## Заголовок

Я сделал локальный firewall для дешёвых AI API, которые пытаются подсовывать команды coding-агентам

## Текст

Сейчас тысячи разработчиков покупают дешёвые OpenAI-compatible API у серых реселлеров.

Проблема в том, что это уже не просто “плохой ответ от модели”. Если ты используешь Claude Code, Cursor, Cline или другой coding-agent, вредоносный провайдер может вставить в ответ `tool_use` / shell payload, а агент сам выполнит это на твоей машине.

Я собрал `carapace` / SafeRouter — локальный guard между агентом и провайдером.

Что он уже умеет:

- proxy перед upstream
- deep-scan с battery из 20 coding-agent сценариев
- model identity confidence
- score / certify / verify
- local registry доверенных провайдеров
- signed feeds
- local SafeRouter UI на `localhost`

Ключевая идея: не просто спросить “endpoint хороший или нет?”, а проверять:

- model honesty
- agent safety
- latency profile
- drift over time
- tool-call safety
- secret handling

То есть ответ уровня:

> Chat-only. Not recommended for coding agents.

Или:

> Agent-safe. Continuously monitored.

Repo: https://github.com/TaroHarado/carapace

Если интересно, дальше могу написать отдельный пост про то, какие probe-сценарии реально ловят unsafe behavior у third-party LLM endpoints.
