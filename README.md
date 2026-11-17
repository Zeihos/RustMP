# RUSTMP

[![Rust CI](https://github.com/Zeihos/RustMP/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/Zeihos/RustMP/actions/workflows/rust.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)
![Status: alpha](https://img.shields.io/badge/status-experimental-orange)

**RUSTMP** — открытый исследовательский проект серверной платформы на **Rust**, ориентированный на сетевую совместимость с **SA-MP 0.3.7** и **open.mp**. Не является официальной разработкой SA-MP/open.mp и не представляет собой готовый игровой мод.

> [!WARNING]
> **Версия 0.2.0-alpha.17 — неиграбельный прототип.** Настоящие клиенты GTA San Andreas пока не могут полноценно подключиться и войти в игровой мир. Результаты автоматических тестов не доказывают совместимость с реальными клиентами. Не открывайте экспериментальный протокол для публичного доступа.

## Текущие возможности

| Подсистема | Статус |
| --- | --- |
| Rust workspace, серверный цикл, конфигурация | Работает, тестируется на Windows и Linux |
| SA-MP UDP Query и офлайн-ответы RakNet | Реализованы и покрыты тестами |
| Кодеки BitStream, ACK, reliable frames, фрагментация | Библиотечные реализации; не полный сетевой стек |
| Pre-auth handshake и retry | Экспериментальная диагностика **только на 127.0.0.1** |
| Анализ PCAP, отслеживание offline handshake | CLI `rustmp-trace`; синтетические тесты |
| Аутентификация реального клиента, игровые RPC, синхронизация | Не реализованы |
| Pawn/AMX, полноценные игровые режимы и плагины | Не реализованы |

Подробный статус по этапам — [PORTING_PLAN.md](PORTING_PLAN.md). История версий — [CHANGELOG.md](CHANGELOG.md).

## Быстрый старт

**Требования:** установленный [Rust и Cargo](https://rustup.rs/) (stable), Git и Windows или Linux. Команды выполняются из корня репозитория.

```bash
git clone https://github.com/Zeihos/RustMP.git
cd RustMP
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
```

Запуск диагностического UDP-сервера:

```bash
cargo run --locked --release -p rustmp-server -- --config config.json
```

По умолчанию в `config.json` указан `127.0.0.1:7777`: сервер доступен только на этой машине. Для проверки SA-MP Query во втором терминале:

```bash
cargo run --locked -p rustmp-protocol --example query_client -- 127.0.0.1 7777
```

Для проверки офлайн-обмена RakNet:

```bash
cargo run --locked -p rustmp-transport --example offline_probe -- 127.0.0.1:7777
```

На Windows также доступны `test-windows.bat` и `start-windows.bat`.

### Экспериментальный pre-auth (локально)

```bash
cargo run --locked -p rustmp-server -- --bind 127.0.0.1 --port 7777 --experimental-preauth
```

Флаг включает ограниченный диагностический транспортный обмен; **он не подключает игрового клиента**. Запуск с этим флагом на `0.0.0.0`, публичном IP или IPv6 запрещён кодом сервера. Для локальных протокольных пробников доступны `local_preauth_probe` и `local_cookie_probe` в `rustmp-protocol/examples/`.

### Анализ сохранённого сетевого захвата

```bash
cargo run --locked -p rustmp-protocol --bin rustmp-trace -- capture.pcap --port 7777 --handshakes
```

`rustmp-trace` читает **классический PCAP**, распознаёт известные offline-пакеты и фиксирует повторы/пропуски **в захвате**. IP-адреса скрыты по умолчанию; содержимое пакетов не печатается. Инструкция и ограничения — [TRACE_ANALYSIS.md](TRACE_ANALYSIS.md).

## Структура репозитория

```text
crates/
  rustmp-core/        Пулы объектов и модель серверного мира
  rustmp-protocol/    SA-MP Query, BitStream, RakNet-кодеки, PCAP-анализатор
  rustmp-transport/   Offline gateway, ACK/retry, pre-auth, сессии
  rustmp-server/      UDP-сервер и локальная диагностика
.github/              CI, шаблоны Issues и Pull Requests
config.json           Локальная конфигурация
```

Технические границы подсистем описаны в [ARCHITECTURE.md](ARCHITECTURE.md).

## Разработка

Проверить workspace:

```bash
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
```

GitHub Actions выполняет проверки на **Linux и Windows**. Тесты используют синтетические пакеты и локальные UDP-сокеты, включая запуск отдельного процесса сервера. **Реальных захватов SA-MP/open.mp клиентов в репозитории пока нет.**

Исправления и предложения приветствуются: [CONTRIBUTING.md](CONTRIBUTING.md). О потенциальных уязвимостях сообщайте согласно [SECURITY.md](SECURITY.md), не публикуя пароли, сетевые дампы и готовые эксплойты в открытых Issues.

## Лицензия и источники

Собственный код RUSTMP распространяется по [MIT](LICENSE). Совместимость исследуется по опубликованным материалам и исходникам [open.mp](https://github.com/openmultiplayer/open.mp), [форка RakNet openmultiplayer](https://github.com/openmultiplayer/RakNet) и [SA-MP](https://github.com/Alf21/samp). Их названия принадлежат соответствующим правообладателям.

Перенос исходных файлов сторонних проектов требует отдельного соблюдения их лицензий (в частности, MPL-2.0 там, где применимо). Наличие совместимого протокола не подразумевает официальной аффилиации.
