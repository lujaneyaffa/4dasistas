# Reply to Apple App Review — Guideline 2.1 (Information Needed), submission 32f376b8

Paste the text under "REPLY" into App Store Connect → App Review → "Reply to App Review".
Paste the same text into App Information → App Review Information → **Notes**.
Attach the screen recording to the reply (see "Screen recording" below).

---

## REPLY

Hello App Review,

Thank you for the review. Here is the information requested for 4DS (iOS 1.0, build 5).

**1. Screen recording**
Attached: a screen recording captured on a physical iPhone running the latest iOS. It starts with launching the app and shows: creating an account, signing in, browsing the calendar and signing up to an event, posting an idea, opening the profile, and deleting the account (Profile → Edit profile → "Delete my account").

**2. Purpose and audience**
4DS (4dasistas) is a community app for Muslim women in the Greater Toronto Area. It brings together, in one place, the group's events and calendar, clubs and activities, local resources and businesses recommended by members, and a women-only badminton league with standings. It solves the problem of community events being scattered across group chats and social posts, so members can find what is on and sign up in one tap. The audience is women 18+ in the GTA; the app is free.

**3. How to access the main features**
Sign in with this demo account (username and PIN, no email or SMS needed):
- Username: `test`
- PIN: `1234`
Main features are in the bottom bar: Home (today's events and clubs), Calendar (month/week/list, tap an event to see details and sign up), Leaderboards (trophy icon: badminton standings), Search (resources and business directory with map), Profile (your details, notifications, "Delete my account").
To create a new account instead: Profile → Sign up → enter a name, username and 4-digit PIN. Account deletion: Profile → Edit profile → "Delete my account…" (asks for the PIN, then removes the profile and all data linked to it).

**4. External services used**
- Cloudflare (hosting, database and storage for the app's content and accounts)
- Apple Push Notification service (push notifications) and Firebase Cloud Messaging (Android only)
- Google Maps Platform (place search and map on events and the directory)
- OpenStreetMap map tiles (directory map)
- Resend (transactional email to the organiser)
- Instagram's public embed (shows a profile preview when a member recommends a resource)
There are no In-App Purchases and no digital goods or subscriptions. Some real-world events have a fee paid to the organiser for the event itself (a physical activity), outside the app.

**5. Regional differences**
The app works the same in every region. Content is focused on the Greater Toronto Area, but no features are region-locked.

**6. Regulated industry / third-party material**
Not applicable. The app is not in a regulated industry and contains no protected third-party material. Content is created by the organisers and members.

Safety: members can report a concern from Profile → "Report a concern", and the organisers moderate all user-submitted content. Privacy policy: https://4dasistas.ca/privacy — Support: https://4dasistas.ca/support

Thank you,
Lujane

---

## Screen recording (you do this part, on your iPhone)
Apple needs it recorded on a real iPhone, starting from launching the app.
1. Settings → Control Center → add "Screen Recording".
2. Open Control Center, tap the record button, wait for the 3-second countdown, open the **4DS** app (from TestFlight or the build Apple has) and go through: sign in, calendar → open an event → sign up, the clubs section on Home → ideas, Profile → Edit profile → scroll to "Delete my account" (you can stop before pressing the final delete, or use a throwaway account to show it working).
3. Stop recording (red status bar → Stop). Find it in Photos, AirDrop or email it to your Mac, and attach it in the reply (App Store Connect accepts .mov / .mp4).
Keep it under ~3 minutes.

## After replying
Apple says if only information was missing, you don't need to resubmit a new build — just reply in the App Review page and they re-review. The page also has a "Resubmit to App Review" button; only press it if Apple's reply says to.
