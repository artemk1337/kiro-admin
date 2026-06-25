# YooKassa SBP bridge для New API

Сервис добавляет оплату через ЮKassa/СБП без патча New API. New API можно обновлять штатно: bridge живет отдельно и после оплаты создает одноразовый redeem-код через `/api/redemption/`.

Для встроенного платежного шлюза New API bridge также реализует Epay-compatible endpoint `/pay/submit.php`. В этом режиме New API сам создает заказ, а bridge только проводит оплату через ЮKassa и отправляет Epay notify обратно в New API.

## Схема

```text
https://vibecode-api.online/pay/
  -> yookassa-bridge
  -> YooKassa payment_method_data.type=sbp
  -> webhook /pay/webhook/yookassa
  -> New API /api/redemption/
```

## Настройка

1. Скопировать env:

```bash
cp .env.yookassa-bridge.example .env.yookassa-bridge
```

2. Заполнить:

- `YOOKASSA_SHOP_ID`
- `YOOKASSA_SECRET_KEY`
- `NEW_API_ADMIN_TOKEN`
- `NEW_API_ADMIN_USER_ID`
- `EPAY_PID`
- `EPAY_KEY`
- `TOPUP_PLANS`

`NEW_API_ADMIN_TOKEN` передается в New API как заголовок `Authorization`.
`NEW_API_ADMIN_USER_ID` передается как `New-Api-User`.
`EPAY_PID` и `EPAY_KEY` должны совпадать с настройками New API `EpayId` и `EpayKey`.

3. Запустить:

```bash
docker compose -f docker-compose.yookassa-bridge.yml up -d --build
```

4. В reverse proxy для `vibecode-api.online` добавить проксирование `/pay/` на `127.0.0.1:8090`.

Пример nginx:

```nginx
location /pay/ {
    proxy_pass http://127.0.0.1:8090/pay/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

5. В личном кабинете ЮKassa добавить webhook:

```text
https://vibecode-api.online/pay/webhook/yookassa
```

Событие: `payment.succeeded`.

## Встроенный шлюз New API

В New API нужно выставить:

```text
PayAddress = https://vibecode-api.online/pay
EpayId = vibecode
EpayKey = значение EPAY_KEY
PayMethods = [{"name":"СБП","icon":"LuQrCode","type":"sbp","min_topup":"1"}]
```

После этого пользователь выбирает способ оплаты прямо в стандартной форме пополнения New API.

## Проверка

Открыть:

```text
https://vibecode-api.online/pay/
```

После оплаты страница покажет redeem-код. Пользователь активирует его в New API.

## Идемпотентность

Bridge хранит заказы в `DATA_FILE`. Повторный webhook по одному платежу не создает второй redeem-код, если код уже был выпущен.
