# SettlementAgent: Безопасная архитектура управления средствами

## 📘 Введение

`SettlementAgent` — это умный контракт, разработанный для безопасного автоматизированного списания средств с кошельков пользователей по заданным правилам и лимитам. Контракт не оказывает кастодиальных услуг — средства всегда находятся под контролем пользователя, а списание возможно только в пределах его явного разрешения.

---

## 🔐 Механизмы безопасности

Контракт реализует несколько уровней защиты от несанкционированных действий:

- **Ролевой доступ:** только адреса с ролью `MANAGER_ROLE` могут инициировать списание средств.
- **Проверка лимитов:** каждый перевод проверяется на соответствие дневным, 10-минутным и глобальным лимитам.
- **Контроль комиссии:** комиссия не может превышать установленный максимум.
- **Версионность разрешения:** клиент явно подтверждает работу только с текущей версией контракта.
- **Фиксированный settlement-адрес:** он задаётся при деплое и не может быть изменён.

---

## ✅ Подтверждение клиентом

Перед списанием средств пользователь должен вызвать функцию `allowLimit()`:

- Устанавливается глобальный лимит, равный текущему `approve` в ERC20 токене.
- Фиксируется версия контракта, на которую пользователь дал согласие.

Это означает:

- Менеджеры не могут использовать старые разрешения после обновления контракта.
- Пользователь контролирует лимит, комиссию и адрес назначения средств.
- Все действия можно отозвать через `approve(0)`.

---

## ⚙️ Прозрачность и управление

- Комиссия (`feePercent`) фиксирована при деплое и изменить её нельзя.
- Индивидуальные комиссии можно установить через `FEEMANAGER_ROLE`, но только ниже или равные глобальной.
- Менеджеры не могут сменить адрес получения средств — он жёстко зафиксирован.

---

## 📊 Аудит и контроль

- Все списания логируются (`Withdrawal`, `DetailedWithdrawal`).
- Доступен журнал `getWithdrawalHistory(address)` для анализа всех операций.
- Пользователь может запросить свою конфигурацию через `getClientFullInfo()`.

---

## 💡 Заключение

Контракт обеспечивает безопасный способ проведения автоматизированных платежей, сохраняя при этом полный контроль за средствами у клиента.

- Никакие средства не хранятся в контракте.
- Списание возможно только в рамках подтверждённых лимитов и комиссий.
- Партнёры могут быть уверены в прозрачности расчётов.
- Пользователи — в надёжности и контроле своих средств.

SettlementAgent — это доверие, автоматизация и безопасность, реализованные через проверенные смарт-контрактные практики.
---

## 🧪 Примеры использования и пользовательские сценарии

### 🛍 Сценарий 1: Оплата с виртуальной карты Simple

**Контекст:**  
Клиент хранит средства в USDC на своём кошельке. Компания Simple выпускает виртуальную карту VISA, привязанную к адресу клиента.

**Как работает оплата:**

1. Клиент вызывает `approve(contract, 1000 USDC)` на адрес контракта SettlementAgent.
2. Затем вызывает `allowLimit()`, чтобы зафиксировать лимит и текущую версию контракта.
3. Устанавливает лимиты списаний: `setTimeLimits(200 USDC / 10 мин, 500 USDC / 24 ч)`
4. При оплате товара через виртуальную карту (например, в магазине) менеджер Simple вызывает `withdrawFromClient(...)`.
5. Контракт проверяет:
   - версию контракта, разрешённую клиентом;
   - не превышен ли лимит;
   - хватает ли approve и баланса;
   - соответствует ли комиссия правилам.
6. Выполняется списание:
   - основная сумма на settlement-адрес;
   - комиссия — на fee-адрес.
7. Клиент может просмотреть историю через `getWithdrawalHistory(...)`.

---

### 🎯 Сценарий 2: Отзыв разрешений

Клиент в любой момент может:

- вызвать `approve(contract, 0)` — полностью отозвать разрешение списывать средства;
- изменить лимиты;
- получить полную информацию через `getClientFullInfo(...)`.

---

### 🛡 Безопасность

- Контракт не имеет доступа к средствам без разрешения.
- Все действия прозрачны, лимиты — на стороне клиента.
- Settlement-адрес зашит при деплое — не может быть подменён.
- Невозможно списать средства в обход лимитов или на другой адрес.



