# Архитектура RUSTMP

RUSTMP — экспериментальный Cargo workspace (Rust 2021) из четырёх крейтов. Задача — постепенно исследовать wire-совместимость старого протокола SA-MP/open.mp с независимой реализацией на Rust.

## Компоненты

| Крейт | Ответственность | Ограничения |
| --- | --- | --- |
| `rustmp-protocol` | UDP Query, BitStream, legacy frame/ACK кодеки, PCAP `rustmp-trace` | Не удостоверяет клиентов и не реализует все RPC |
| `rustmp-transport` | Offline RakNet, cookie, retransmit, split assembly, pre-auth и заготовка сессий | Реальный игровой клиент не подключён; `VerifiedSessions` используется как библиотека |
| `rustmp-core` | Пулы ID/сущностей и модель мира | Не синхронизирует игроков с GTA |
| `rustmp-server` | UDP loop, конфигурация, маршрутизация Query/offline, localhost-пробник | Экспериментальный handshake не даёт игрового входа |

## Схема выполнения

```text
    UDP datagram
         |
  rustmp-server
         |
   +-----+----------------------------+
   |                                  |
SA-MP Query                   RakNet offline
   |                                  |
query snapshot                  OfflineGateway
   |                                  |
reply                              [pre-auth]
                                      |
                         localhost-only experimental path
                                      |
                     ACK / retry / handshake (diagnostic)
                                      |
                         discard unverified client
```

`World` хранит внутренние тестовые структуры, но **не** подключённых пользователей. Нельзя трактовать `OfflineGateway` pending slots, завершение pre-auth транскрипта или результаты PCAP-анализа как подтверждённый игровой вход.

## Подтверждённые тестами возможности

- Команды `cargo check --locked --workspace --all-targets`, `cargo test --locked --workspace` работают в GitHub Actions на Windows и Linux.
- Синтетические wire-векторы и повреждённые пакеты покрыты unit-тестами.
- UDP-интеграционные тесты запускают реальный процесс сервера только на localhost.
- `rustmp-trace` анализирует классические PCAP без вывода payload, но сам PCAP может содержать секреты.

## Необходимые этапы до игрового сервера

1. Получить легитимные клиентские PCAP и сверить wire-поля с обеими версиями RakNet, включая cookie/auth и тайминги.
2. Реализовать и проверить публично-безопасный handshake с защитой от spoofing/replay, а также полноценный транспорт.
3. Реализовать RPC, проверку версии и игровую аутентификацию, создание игроков и синхронизацию.
4. Добавить Pawn/AMX, игровые сущности и совместимость с конкретными модами.
5. Выполнить fuzzing, нагрузочные и межклиентские испытания прежде, чем объявлять публичную готовность.

Детальный прогресс см. в [PORTING_PLAN.md](PORTING_PLAN.md). Референсы и лицензионные ограничения — в [README.md](README.md).
