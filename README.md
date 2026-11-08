# open.mp / SA-MP → Rust — 0.2.0-alpha.1

> **Техническая alpha-версия, НЕ готовый игровой сервер.** Существующие клиенты GTA San Andreas пока не могут войти. Все объекты и игроки из `omp-core` используются лишь как внутренние структуры данных и тестовые фикстуры.

Это самостоятельная попытка реализовать серверную платформу open.mp на Rust, **не** игровой RP-мод и **не** обёртка над C++.

## Что реализовано

- Cargo workspace из четырёх Rust-крейтов: `omp-server`, `omp-core`, `omp-protocol`, `omp-transport`.
- Обработка SA-MP UDP Query `i`, `r`, `c`, `d`, `p` в том же UDP-сокете, что и RakNet.
- **Новый этап 0.2.0-alpha.1:** первый офлайн-обмен старого RakNet из SA-MP: `ID_OPEN_CONNECTION_REQUEST` (3 байта) → `ID_OPEN_CONNECTION_REPLY` (2 байта).
- Обработка старого unconnected RakNet ping (5 байт, timestamp) и pong (5 байт). Дополнительные серверные данные для pong пока не формируются.
- Отдельный модуль `omp-transport` с лимитом запросов на IP, ограничением незавершённых слотов, ограничением памяти счётчика IP, таймаутом незавершённых подключений.
- Пул игроков и транспорта, серверный мир, начальный BitStream, кодировки CP1251/CP1252.
- Тесты кодирования пакетов, таймаутов, повтора/флуда и совместного использования UDP-порта.
- GitHub Actions CI (Linux/Windows) и простой клиент проверки offline handshake.

**Не реализованы:** RakNet reliability / ACK, полноценное соединение и авторизация, шифрование, RPC, создание игроков в реальном клиенте, игровые данные и синхронизация, Pawn AMX, плагины open.mp. `pending`-слот **не** означает подключённого игрока.

## Как проверить на Windows

1. Установить Rust + Cargo: https://rustup.rs/.
2. Распаковать весь ZIP.
3. Запустить `test-windows.bat` (проверка Cargo workspace) или вручную:

```powershell
cargo check --workspace --all-targets
cargo test --workspace
```

4. Запустить `start-windows.bat` или:

```powershell
cargo run --release -p omp-server -- --config config.json
```

5. Во втором PowerShell проверить SA-MP Query:

```powershell
cargo run -p omp-protocol --example query_client -- 127.0.0.1 7777
```

6. Проверить **отдельно офлайн-пакет** старого RakNet:

```powershell
cargo run -p omp-transport --example offline_probe -- 127.0.0.1:7777
```

При успешном ответе увидите двубайтовый ответ и сообщение `Offline pre-handshake response received`. **Это не проверка игрового подключения**. Для проверки реального подключения понадобятся клиент SA-MP и реализованный RakNet reliability layer.

## Структура

```text
Cargo.toml                          рабочее пространство Rust
crates/omp-protocol/               SA-MP Query, BitStream и тестовый query-клиент
crates/omp-transport/              legacy RakNet offline bootstrap и offline_probe
crates/omp-core/                   мир, структура игрока, транспорт и ID pools
crates/omp-server/                 UDP event loop, маршрутизация пакетов, ограничения
.github/workflows/rust.yml         cargo check и test для Windows и Linux
config.json                         подмножество конфига open.mp
PORTING_PLAN.md                     план полного порта
CHANGELOG.md                        изменения между версиями
```

## Особенность протокола

У **старого** форка RakNet, используемого SA-MP/open.mp, формат первичного UDP-запроса не совпадает с двухшаговой схемой *современного* RakNet (MTU + `0x05`/`0x07`). Для первой итерации использованы опубликованные исходники старого форка:

- https://github.com/openmultiplayer/RakNet/blob/master/Source/RakPeer.cpp
- https://github.com/Alf21/samp/blob/master/raknet/PacketEnumerations.h
- https://github.com/openmultiplayer/open.mp

Числовые wire ID перенесены из старого enum с учётом `ID_DUMMY_*`. Для окончательной совместимости их требуется сверить с собранным бинарником актуального open.mp и настоящим SA-MP-клиентом. Не смешивайте этот код с современным RakNet/Minecraft Bedrock.

## Ограничения и лицензия

- В разработке применён безопасный Rust без unsafe и без включения исходных C++ файлов.
- Собственные исходники прототипа — MIT; при последующем переносе файлов open.mp нужно соблюдать MPL-2.0 и соответствующие notices, а при переносе сторонних библиотек — их отдельные лицензии.
- Пока **нет** `cargo`/`rustc` в среде сборки архива, поэтому здесь не утверждается, что проект был скомпилирован и что тесты прошли. Исходники и тесты подготовлены; запускайте команды выше или в GitHub Actions.
- До fuzzing и нагрузочных тестов экспонировать прототип в публичный интернет не рекомендуется.
