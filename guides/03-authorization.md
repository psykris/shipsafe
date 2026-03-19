# Guide 03 — Authorization and Access Control

> **Who this is for:** Your users can log in, but can they see data that belongs to other users? This guide explains the most common authorization failures in AI-generated code and how to fix them.

---

## Authentication vs Authorization

These two words are often confused:

- **Authentication** = proving who you are ("I am user #42")
- **Authorization** = deciding what you're allowed to do ("user #42 can only see their own orders")

Passing authentication doesn't automatically mean you're authorized. This distinction is where AI-generated code most commonly fails.

---

## The Hotel Room Analogy

Think of a hotel. Authentication is getting a key card at the front desk. Authorization is whether your key card opens room 412, the pool, the executive lounge, and the gym. Just having a key card doesn't mean you can walk into every room. Your app needs the same layered access control.

---

## BOLA — Broken Object Level Authorization (OWASP API #1)

BOLA (also called IDOR — Insecure Direct Object Reference) is the #1 API vulnerability. It happens when your code lets users access resources by ID without checking if they *own* that resource.

### What it looks like

```python
# DANGEROUS — any authenticated user can read any order
@app.route("/api/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.get(order_id)  # No ownership check!
    return jsonify(order.to_dict())
```

An attacker simply changes the number in the URL:
- `GET /api/orders/1001` → their order ✓
- `GET /api/orders/1002` → someone else's order ✗ but it works

### The fix

```python
@app.route("/api/orders/<int:order_id>")
@login_required
def get_order(order_id):
    # SAFE — filter by both ID and the current user
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id  # Ownership check
    ).first_or_404()
    return jsonify(order.to_dict())
```

**Django ORM equivalent:**
```python
order = get_object_or_404(Order, pk=order_id, user=request.user)
```

**Prisma (Next.js) equivalent:**
```javascript
const order = await prisma.order.findUnique({
  where: {
    id: orderId,
    userId: session.user.id, // ownership check
  },
});
if (!order) return res.status(404).json({ error: 'Not found' });
```

---

## RBAC — Role-Based Access Control

For apps where different user types need different permissions (user, moderator, admin), use RBAC.

### The pattern

```python
# Define roles as constants — not magic strings everywhere
class Role:
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"

# Decorator for role checking
from functools import wraps

def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"error": "Unauthorized"}), 401
            if current_user.role != role:
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# Usage
@app.route("/api/admin/users")
@require_role(Role.ADMIN)
def list_all_users():
    return jsonify(User.query.all())
```

---

## Supabase Row Level Security (RLS)

If you're using Supabase (the most common vibe-coding backend), Row Level Security is your primary authorization tool. It enforces ownership at the database level — even if your backend code has a bug, the database won't return data the user shouldn't see.

### Enable RLS

```sql
-- Enable RLS on your table
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

-- Policy: users can only see their own orders
CREATE POLICY "Users can view own orders"
ON orders FOR SELECT
USING (auth.uid() = user_id);

-- Policy: users can only insert their own orders
CREATE POLICY "Users can insert own orders"
ON orders FOR INSERT
WITH CHECK (auth.uid() = user_id);
```

**Without RLS enabled, any authenticated user can read the entire table.** This has caused multiple real data breaches in Supabase apps.

---

## Multi-Tenancy Isolation

If your app serves multiple organizations (tenants), every query must be scoped to the correct tenant.

```python
# DANGEROUS — no tenant scoping
def get_customers():
    return Customer.query.all()  # Returns ALL tenants' customers!

# SAFE — always scope to current tenant
def get_customers():
    return Customer.query.filter_by(
        tenant_id=current_user.tenant_id
    ).all()
```

A common pattern is to make `tenant_id` part of every query through a base query class:

```python
class TenantScopedQuery(BaseQuery):
    def get_or_404(self, *args, **kwargs):
        obj = super().get_or_404(*args, **kwargs)
        if obj.tenant_id != current_user.tenant_id:
            abort(404)  # Pretend it doesn't exist
        return obj
```

---

## Admin Endpoints

Admin functionality needs double protection: first verify authentication, then verify the admin role. Don't rely on hiding the URL.

```python
@app.route("/api/admin/delete-user/<int:user_id>", methods=["DELETE"])
@login_required          # Check 1: must be logged in
@require_role(Role.ADMIN)  # Check 2: must be admin
def delete_user(user_id):
    # Check 3: audit log before destructive actions
    AuditLog.create(
        action="delete_user",
        target_id=user_id,
        actor_id=current_user.id,
    )
    User.query.filter_by(id=user_id).delete()
    return jsonify({"deleted": user_id})
```

---

## Authorization Checklist

- [ ] Every route that returns user data filters by `user_id` (or equivalent ownership field)
- [ ] Admin routes check role in addition to authentication
- [ ] Supabase tables have RLS enabled with appropriate policies
- [ ] Multi-tenant apps scope every query to `tenant_id`
- [ ] Deleting or modifying resources verifies ownership before acting
- [ ] 404 is returned (not 403) when a user tries to access another user's resource (don't leak that it exists)
- [ ] Sensitive actions (delete, transfer, publish) are written to an audit log

---

*Next: [Guide 04 — Input Validation and Injection Prevention](04-input-validation.md)*
