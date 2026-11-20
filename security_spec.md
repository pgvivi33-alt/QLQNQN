# Security Specification (`prompts` Collection)

## 1. Data Invariants
1. Public guests (unauthenticated) may only read (`get`, `list`) documents in `/prompts/{promptId}`.
2. Write operations (`create`, `update`, `delete`) in `/prompts/{promptId}` are strictly restricted to the verified administrator (`request.auth != null && request.auth.token.email_verified == true && request.auth.token.email == 'pgvivi33@gmail.com'`).
3. Every other collection or document path outside `/prompts` is strictly denied for both reading and writing.
4. Every document in `/prompts/{promptId}` must have a valid `promptId` matching `^[a-zA-Z0-9_\-]+$` with length <= 128.
5. Every document must contain strictly the exact 4 keys: `title`, `category`, `content`, `createdAt` (no shadow/ghost fields).
6. `title` must be a non-empty string with `1 <= title.size() <= 100`.
7. `category` must be one of `'사진 합성'`, `'스타일 변환'`, `'캐릭터·포스터'`.
8. `content` must be a non-empty string with `1 <= content.size() <= 10000`.
9. `createdAt` must be a Firestore timestamp equal to `request.time` on creation, and immutable thereafter (`incoming().createdAt == existing().createdAt`).

## 2. Dirty Dozen Payloads (All Must Fail with `PERMISSION_DENIED`)
1. Unauthenticated guest attempts `create`, `update`, or `delete` on `/prompts/{promptId}`.
2. Signed-in non-admin user (`email != 'pgvivi33@gmail.com'`) attempts `create`, `update`, or `delete`.
3. Spoofed admin email with `email_verified == false` attempts write.
4. Admin sends ghost field on create: `{ title, category, content, createdAt, isAdmin: true }`.
5. Missing required field on create: `{ title, category, createdAt }` (no `content`).
6. Invalid category enum: `{ title: "Test", category: "기타", content: "Body", createdAt }`.
7. Oversized title (> 100 chars) on create/update.
8. Oversized content (> 10000 chars) Denial-of-Wallet payload.
9. Client-spoofed `createdAt` timestamp (not equal to `request.time`) on create.
10. Mutating `createdAt` on update.
11. Invalid document ID poisoning (`promptId` with spaces/slashes or > 128 chars).
12. Any read or write on collections other than `/prompts` (e.g., `/users/1`, `/test/connection`, `/admins/1`).
