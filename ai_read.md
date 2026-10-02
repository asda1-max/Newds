# NEWDS — Build Plan

## Product goal
NEWDS is a personal notes vault: a notes-first web app for capturing text, links, images, and other files. It should feel polished and interactive, with a rose-gold and violet visual identity.

## Technology and initial scope
- Python Flask web application with SQLite.
- Flask sessions for signed-in state; bcrypt password hashing for account passwords.
- Tailwind CSS CDN and Google Fonts for the interface, with lightweight built-in JavaScript interactions and transitions.
- Local backend file storage for uploaded attachments in this single-user-development-stage deployment.
- Registration is capped at five total accounts.
- Reminders are checked and displayed when a user logs in; no background notification service is required.

## Functional build plan

### 1. Application foundation
- Create a maintainable Flask app with separate modules for configuration, database access, authentication, notes, and file handling where appropriate.
- Read the Flask secret key and storage/database locations from environment configuration, with safe development defaults where suitable.
- Initialize SQLite tables automatically and keep uploaded content outside the public static directory.

### 2. Accounts and access control
- Provide register, login, and logout flows.
- Hash passwords with bcrypt; never store raw passwords.
- Enforce a hard cap of five registered accounts when handling registration.
- Protect dashboard and note routes behind authentication.
- Scope every note and attachment operation to the currently signed-in user.
- Use CSRF protection for state-changing forms and validate inputs on the server.

### 3. Data model
- Users: ID, username, password hash, creation time.
- Notes: ID, owner ID, title, body/content, encrypted flag, optional reminder date, created and updated timestamps.
- Attachments: ID, note ID, owner ID, stored name, original display name, MIME type, byte size, encrypted flag, creation time.
- Reminder delivery state: track reminder milestones for each note so H-3/H-2/H-1 are shown once per milestone.

### 4. Notes experience
- Support creating, viewing, editing, deleting, and searching notes.
- Notes support text and URLs, plus multiple attachments.
- Provide a paperclip-style attachment control in the editor.
- Show image previews in note details and downloadable file rows for other file types.
- Use safe generated storage names; retain the original filename only as display metadata.
- Validate ownership for preview, download, and deletion. Remove stored files when an attachment or note is deleted.

### 5. Attachments and upload limits
- All uploaded images and other files are stored by the backend; SQLite stores metadata and references, not the file bytes.
- Every file must be strictly smaller than 1 GB (1,073,741,824 bytes).
- Images must be strictly smaller than 10 MB (10,485,760 bytes); the image-specific limit applies even though the general file limit is larger.
- Enforce limits while receiving uploads as well as validating the resulting file size. Configure Flask request limits to allow a note plus multiple permitted files without accepting an unbounded request.
- Permit common image, document, and archive types while allowing other non-executable user files subject to the size cap; reject unsafe executable/server-interpreted formats.
- Never serve an upload as executable content. Serve owned downloads as attachments and image previews with a validated image MIME type.

### 6. Encrypted notes and attachments
- At note creation, allow the user to select ordinary or password-encrypted mode.
- Encrypt both note content and every attachment belonging to an encrypted note using a vetted cryptography library and password-based key derivation; do not invent cryptographic primitives.
- Do not store the encryption password or derived key. Store the salt and authenticated-encryption metadata needed to derive/decrypt later.
- Request the note password when opening an encrypted note. Decrypt attachment data only after successful unlock; encrypted files remain ciphertext at rest.
- Clearly explain that forgetting the note password makes encrypted content and attachments unrecoverable.
- Ensure edits and attachment additions preserve the note's encryption mode and use the password supplied for that operation.

### 7. Login-time reminders
- Let users set a reminder date on a note.
- On successful login, check reminders and show due-soon notices for H-3, H-2, and H-1 in the dashboard.
- Display each milestone once and persist its delivery state so logging in repeatedly does not repeat it.
- Keep this check synchronous at login; no scheduler, email, push notification, or background worker is needed.
- Past-due behavior: show overdue reminders at login as overdue until dismissed/handled, without fabricating missed H-3/H-2/H-1 messages.

### 8. UI and interaction
- Build responsive login, registration, dashboard, note editor, note detail, and unlock interfaces.
- Use an elegant rose-gold/violet palette, Tailwind CDN, and Google Fonts.
- Add polished note cards, search, attachment previews, reminder badges, empty states, and clear feedback for actions.
- Add lightweight JavaScript animations, including smooth swipe-like dashboard-to-note transitions.
- Respect reduced-motion preferences and keep interactions usable on mobile and keyboard-accessible.

### 9. Delivery and verification sequence
1. Initialize Flask configuration, dependencies, SQLite schema, and upload storage.
2. Implement authentication, bcrypt hashing, session protection, CSRF, and five-account cap.
3. Implement note CRUD, search, dashboard, and ownership checks.
4. Implement backend attachment storage, validation, previews, downloads, and cleanup.
5. Implement encryption for note bodies and attachments, including unlock and edit flows.
6. Implement reminder checks at login and persistent H-3/H-2/H-1 delivery state.
7. Polish responsive rose-gold/violet UI and transitions.
8. Verify registration cap, authentication, user data isolation, note CRUD, upload boundaries, encrypted attachment round trips, and login-time reminders.

## Initial implementation assumptions
- This is a personal development deployment; uploaded files are kept on the same machine in a private backend storage directory.
- The file-size limits are per file and strict: 1 GB is the maximum for non-image files; image files have the stricter 10 MB maximum.
- Encryption is application-level authenticated encryption for both note text and attachments.
