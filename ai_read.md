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
- Permit common image, document, and archive types while allowing other user files subject to the size cap. Unsafe executable/server-interpreted formats must be encrypted at rest as escrow files and downloaded only with a `.NEWDS` suffix.
- Never serve an upload as executable content. Decrypt escrow files only for an authenticated owner's explicit download, serve them as `application/octet-stream` attachments under the original filename, and allow inline image previews only for validated raster image extensions.

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

---

# NEWDS — Long-Term All-in-One Roadmap

The following phases describe the planned evolution of NEWDS from a polished personal notes vault into an all-in-one private personal operating system. Each phase should be implemented incrementally and verified before moving to the next phase.

## Current feature baseline

Already implemented in the current build:
- Flask, SQLite, bcrypt login, CSRF protection, and a five-account registration cap.
- Notes with text, links, multiple backend-stored attachments, image previews, and downloads.
- Password-based authenticated encryption for encrypted note bodies and attachments.
- Login-time H-3, H-2, H-1 reminders.
- Rose-gold/violet responsive interface with editor wipe transitions.
- Direct editing for ordinary notes; encrypted notes go through an unlock page first.
- Mood themes: Lavender Haze, Rose Latte, Midnight, and Sunday Paper.
- Pinned notes, drag-to-reorder cards, daily thought, quick capture, random memory, focus mode, ambient visual mode, journaling streak, unlock reveal, and attachment lightbox.

## Phase 1 — Daily-use foundations

### 1. Universal search and filters
- Search note titles, ordinary note bodies, attachment display names, tags, moods, and reminder dates.
- Keep encrypted note contents excluded from plaintext search unless the note is unlocked in the current session.
- Add filter chips and query operators:
  - `is:encrypted`
  - `is:pinned`
  - `has:file`
  - `mood:rose`
  - `before:YYYY-MM-DD`
  - `after:YYYY-MM-DD`
- Show result counts, active filters, and a clear-all control.
- Add indexes for fields used by common searches.

### 2. Tags and collections
- Add a reusable tags table and a note-to-tags join table.
- Allow multiple tags per note, with safe normalized names.
- Provide tag suggestions based on existing tags.
- Add dashboard collections:
  - All Notes
  - Pinned
  - Encrypted
  - With Attachments
  - Reminders
  - Daily Thoughts
  - Custom tags
- Keep mood and tags separate: mood controls atmosphere, tags control organization.

### 3. Trash and restore
- Replace immediate permanent deletion with a trash state.
- Add a Trash page with restore and permanent-delete actions.
- Add an Empty Trash confirmation flow.
- Keep deleted notes and attachment references recoverable until permanent deletion.
- Add optional automatic cleanup after 30 days.
- Ensure encrypted files remain encrypted while in Trash.

### 4. Backup, export, and import
- Export one note as Markdown and HTML.
- Export selected notes or the complete vault as a ZIP.
- Include attachments and a manifest containing note metadata.
- Create an encrypted full-vault backup protected by a separate backup password.
- Provide an import flow with validation, duplicate handling, and a preview before committing.
- Add a backup health indicator and last-backup timestamp in Settings.
- Never include login passwords or encryption passwords in plaintext exports.

### 5. Checklist and task mode
- Add checklist blocks inside notes.
- Support checked/unchecked items, ordering, and quick completion toggles.
- Add optional due dates and priority labels for checklist items.
- Provide a lightweight Tasks view without turning NEWDS into a complex project-management tool.
- Allow converting a checklist item into a separate note.

### 6. Settings and vault lock
- Create a Settings page for account, appearance, storage, animation, and privacy preferences.
- Add a manual Lock Vault button.
- Add optional inactivity auto-lock.
- Support a local PIN or re-authentication gate for returning to an unlocked session.
- Add a reduced-motion preference and ambient-mode preference.
- Add account password change with current-password verification.

## Phase 2 — Journaling and time-based memory

### 7. Journal mode
- Add a dedicated Journal entry type with an automatic date.
- Make encryption the default for journal entries, while allowing the user to change it.
- Support mood, energy level, reflection prompts, and optional attachments.
- Add prompts such as:
  - What is occupying your mind today?
  - What went well today?
  - What do you want to let go of?
  - What should your future self remember?
- Keep journal entries compatible with universal search and export.

### 8. Calendar and timeline views
- Add a monthly calendar showing notes, daily thoughts, journal entries, and reminders.
- Add a chronological timeline view for recent activity.
- Clicking a date should show all entries from that date.
- Support keyboard navigation and responsive mobile calendar behavior.

### 9. On This Day
- Find entries created on the same month/day in previous years.
- Show an optional login-time card: “On this day…”
- Respect encryption: locked notes show only safe metadata until unlocked.
- Allow dismissing the card for the current session.

### 10. Templates
- Add templates for:
  - Daily journal
  - Brain dump
  - Meeting notes
  - Book notes
  - Movie notes
  - Travel plan
  - Shopping list
  - Finance log
  - Idea canvas
  - Letter to future self
- Let users create and save custom templates.
- Keep template selection available from Quick Capture and the new-note flow.

### 11. Mood analytics
- Show simple, non-clinical visual summaries by week and month.
- Display mood counts, journaling frequency, and note creation patterns.
- Use language of reflection rather than diagnosis.
- Never infer mental-health conditions from mood data.

## Phase 3 — Distinctive NEWDS identity

### 12. Rich text editor
- Replace the basic textarea with a progressively enhanced editor.
- Support bold, italic, headings, quote blocks, bullet lists, numbered lists, checklists, code blocks, dividers, highlights, and links.
- Preserve a safe plain-text or structured representation for encryption and export.
- Keep keyboard shortcuts and mobile editing comfortable.
- Add autosave drafts only after encrypted draft handling is designed safely.

### 13. Link capture and bookmarks
- Detect pasted URLs and offer a link card.
- Store URL, title, domain, description, and optional thumbnail metadata.
- Add a Bookmarks collection and filters for domains.
- Fetch remote metadata server-side with timeouts and safe URL validation.
- Never allow remote metadata fetching to access internal/private network addresses.

### 14. Web clipper
- Create a small bookmarklet first.
- Accept a URL, page title, selected text, and optional source metadata.
- Add an authenticated capture endpoint with CSRF/token protection.
- Consider a browser extension only after the bookmarklet flow is stable.

### 15. Ambient rooms
- Expand ambient mode into selectable rooms:
  - Rainy Room
  - Late-night Desk
  - Soft Café
  - Violet Silence
  - Rose Morning
- Change background gradients, subtle animations, and optional soundscape.
- Audio must default to off and require an explicit user action.
- Remember the selected room locally without storing unnecessary personal data.

### 16. Memory constellation
- Visualize notes as a constellation of interactive points.
- Color points by mood and group them by shared tags.
- Size points by attachment count, note length, or recency.
- Clicking a point opens the appropriate editor or unlock page.
- Keep a list-based fallback for accessibility and reduced-motion users.

### 17. Easter eggs and quiet delight
- Add time-aware greetings without becoming intrusive.
- Add gentle milestones such as the tenth note or first week of journaling.
- Create rotating captions for Random Memory.
- Add an optional Midnight Mode based on local time.
- Keep all easter eggs reversible and avoid interrupting writing.

## Phase 4 — Advanced personal vault capabilities

### 18. OCR and document intelligence
- Extract text from supported images and PDFs locally where possible.
- Make OCR opt-in for privacy.
- Store extracted text separately and protect it under the same encryption rules as the source note.
- Allow searching OCR text only after explicit indexing consent.

### 19. Secure snippets
- Add a dedicated encrypted content type for recovery codes, API keys, license keys, Wi-Fi notes, and other short secrets.
- Hide content by default and require deliberate reveal.
- Add copy-to-clipboard with temporary confirmation and automatic clearing where practical.
- Do not market this as a full password manager until it has undergone a dedicated security review.

### 20. Activity and audit history
- Record useful local activity such as login, note creation, note deletion, attachment upload, restore, and backup creation.
- Add an Activity page with timestamps and safe descriptions.
- Never log note contents, passwords, encryption keys, or sensitive attachment data.

### 21. Optional local AI assistant
- Consider an opt-in, local-first assistant for:
  - Summarizing a selected note
  - Extracting action items
  - Suggesting tags
  - Finding related notes
  - Generating journal prompts
- Keep AI actions explicitly user-triggered.
- Do not send private content to external services by default.
- Clearly show which note content is being processed.

## Recommended implementation order

1. Universal search and filters.
2. Tags and collections.
3. Trash and restore.
4. Encrypted backup/export/import.
5. Checklist and task mode.
6. Settings and vault lock.
7. Journal mode and calendar view.
8. On This Day and templates.
9. Mood analytics.
10. Rich text editor.
11. Link capture and web clipper.
12. Ambient rooms and memory constellation.
13. OCR, secure snippets, audit history, and optional local AI.

## Definition of done for the roadmap

Every phase is complete only when:
- The feature has an intentional responsive UI.
- Ownership and authorization checks cover every route.
- Encrypted content does not leak through search, previews, logs, exports, or metadata.
- Destructive actions have a recovery path where appropriate.
- Database migrations work against an existing NEWDS installation.
- Keyboard, mobile, reduced-motion, and empty/error states are handled.
- Relevant smoke tests and round-trip tests pass.
- The feature is documented in the README and this file.
