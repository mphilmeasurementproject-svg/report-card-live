# Jukwa Report Card System — Go-Live Guide (GitHub + Supabase + Vercel)

You do NOT need XAMPP, PHP or cPanel any more.

## 1. Supabase (the database)
1. supabase.com -> New project. Name: `report-card`. Choose a strong database password and SAVE IT. Region: closest to Ghana. Wait about 2 minutes.
2. Open **SQL Editor** -> New query.
   - Open `db/1_schema.sql`, copy ALL, paste, click **Run**. (Expect "Success".)
   - New query again. Open `db/2_starting_data.sql`, copy ALL, paste, **Run**.
3. Click **Connect** (top of the page) -> **Transaction pooler** -> copy the connection string.
   Replace `[YOUR-PASSWORD]` in it with your database password. Keep it for step 3.

## 2. GitHub
1. github.com -> New repository -> name `report-card-live` -> **Private** -> Create.
2. Click "uploading an existing file", drag in EVERYTHING inside this folder
   (`api`, `public`, `db`, `package.json`, `vercel.json`, `.gitignore`, `.env.example`, `README.md`) -> Commit.

## 3. Vercel
1. vercel.com -> Add New -> Project -> import `report-card-live`.
2. Leave build settings as they are. Open **Environment Variables** and add (names exactly):

| Name | Value |
|---|---|
| `DATABASE_URL` | the Supabase connection string from step 1.3 |
| `SESSION_SECRET` | any long random text, 40+ characters |
| `ADMIN_INITIAL_PASSWORD` | the password you want for the first login (min 8 chars) |
| `ARKESEL_API_KEY` | your NEW Arkesel key |
| `SMS_SENDER` | `JukwaBasic` |
| `RECOVERY_ADMIN_EMAIL` | the administrator Gmail address |
| `SMTP_USER` | the same Gmail address |
| `SMTP_PASS` | a NEW Gmail App Password (Google Account -> Security -> App passwords) |

3. Click **Deploy**. When it finishes, open the link.

## 4. First login
- Username `admin`, password = what you set in `ADMIN_INITIAL_PASSWORD`.
- The system asks you to change it. Do it immediately.
- Settings: check school name, academic year and term. Add teachers, students, classes.
- Test: send one SMS to your own number, request a recovery email, try the Parent Portal.

## If something goes wrong
- "Server is not configured" -> an environment variable is missing in Vercel. Add it, then Deployments -> Redeploy.
- "The server could not save" -> usually a wrong `DATABASE_URL`. Vercel -> your project -> Logs shows the real error.
- Changed an environment variable? Always Redeploy afterwards.
- SMS fails -> check the Arkesel balance and that the sender ID `JukwaBasic` is approved.
- Email fails -> the Gmail App Password must be the 16-letter one (no spaces), with 2-step verification on.

## Notes
- Backup/restore files above about 4 MB will not upload through Vercel. Use Supabase's own backups for big data.
- Never put real passwords in GitHub. They live only in Vercel Environment Variables.
