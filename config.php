<?php http_response_code(404); exit; ?>
{
  "_readme": "Конфігурація сторінки швидкої оплати ОСББ. Перший рядок не видаляти.",
  "password_hash": "",
  "admin_email": "osbb.dontsia@gmail.com",
  "mail_from": "",
  "site_url": "https://dontsa2a.kyiv.ua/quick-payment/",
  "session_days": 30,
  "timezone": "Europe/Kyiv",
  "default_account": "main",
  "accounts": [
    {
      "id": "main",
      "label": "Основний рахунок ОСББ",
      "name": "ОБ'ЄДНАННЯ СПІВВЛАСНИКІВ БАГАТОКВАРТИРНОГО БУДИНКУ \"ДОНЦЯ 2А-ІНІЦІАТИВА\"",
      "iban": "UA123052990000026009025007543",
      "tax_id": "43352162",
      "bank": "АТ КБ \"Приватбанк\"",
      "mfo": "320649",
      "bank_edrpou": "14360570",
      "phone": "+380639548523",
      "email": "osbb.dontsia@gmail.com",
      "show_phone": true,
      "show_email": true
    }
  ],
  "purposes": [
    "Внесок співвласника",
    "Внесок на утримання будинку",
    "Внесок до ремонтного фонду",
    "Погашення заборгованості за внесками",
    "Інший платіж на користь ОСББ"
  ],
  "default_purpose": "Внесок співвласника",
  "profile": {
    "name": "ОСББ «Донця 2А-Ініціатива»",
    "subtitle": "Швидка оплата внесків та інших платежів",
    "badge": "Приймаємо платежі",
    "footer": "ОСББ «Донця 2А-Ініціатива»",
    "logo_alt": "ОСББ «Донця 2А-Ініціатива»"
  },
  "page": {
    "title": "Швидка оплата — ОСББ «Донця 2А-Ініціатива»",
    "description": "Швидка оплата на рахунки ОСББ «Донця 2А-Ініціатива»"
  },
  "invoice": {
    "title": "РАХУНОК НА ОПЛАТУ",
    "number_start": 1,
    "note": "",
    "show_logo": false
  },
  "payee": {
    "name": "ОБ'ЄДНАННЯ СПІВВЛАСНИКІВ БАГАТОКВАРТИРНОГО БУДИНКУ \"ДОНЦЯ 2А-ІНІЦІАТИВА\"",
    "iban": "UA123052990000026009025007543",
    "tax_id": "43352162",
    "bank": "АТ КБ \"Приватбанк\"",
    "mfo": "320649",
    "bank_edrpou": "14360570",
    "phone": "+380639548523",
    "email": "osbb.dontsia@gmail.com",
    "show_phone": true,
    "show_email": true
  },
  "auth": [],
  "reset": []
}
