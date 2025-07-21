The Most Underrated 0-Click Account Takeover Using Punycode IDN Homograph Attacks
Hackers Are Earning 💸$XX,000+ With This Secret Trick — Now It’s Your Turn
coffinxp
coffinxp

Following
7 min read
·
Jun 13, 2025
670


10






Introduction
Internationalized Domain Name (IDN) Homograph Attacks take advantage of characters from different languages that look nearly identical, such as the Latin “a” and the Cyrillic “а”. While it might look like a regular domain or email on the surface, what’s really happening behind the scenes is a character-swap using similar-looking but technically different Unicode characters.

For example:

Unicode Email: аdmin@example.com
Punycode Format: xn — dmin-7cd@example.com
When systems like email providers or authentication flows fail to properly distinguish between these visually similar characters, it can result in serious vulnerabilities. This includes account takeovers during sign-up, password resets or even bypassing 2FA protections, posing a high risk if not properly mitigated.

Difference between Punycode & IDN Homograph Attacks
What Is Punycode?
Punycode is a way to represent Unicode characters using only the ASCII character set, making it compatible with systems that don’t support Unicode directly, like domain name systems.

Example:

The Unicode email security@gmàil.com (with the special "à" character) becomes:
security@xn--gml-hoa.com
This looks very similar to security@gmail.com, but actually points to a different domain making it a powerful trick used in phishing, account takeover, and 2FA bypass attacks.

What Are IDN Homograph Attacks?
These attacks trick the system (and sometimes the user) into thinking two visually similar strings are the same but under the hood, they’re entirely different.

Example:

"admin@example.com" vs "аdmin@example.com" (Cyrillic "а")
Look identical, don’t they?

Lab Setup & Tools Required
Burp Suite — to intercept and modify HTTP requests
Burp Collaborator — your SMTP/email callback server
Punycode Generator — to encode Unicode characters
No IDN domain or SMTP server is required for this poc. i’ll simulate the attack using Burpsuite only..

Step-by-Step Exploit Walkthrough
Let’s break it down from a simple signup to full-blown account takeover, step by step using lab created by Voorivex’s Team.

Step 1: Register With a Normal Email
Go to any target website that allows email signup could be any login page and register a new account with a normal email. For receiving email callbacks, we’re going to use Burp Collaborator, which acts like your fake SMTP server.

security@gmail.com.bcrkly6yl8ke552nzjt7jtu52w8nwdk2.oastify.com

Validate Account Functionality
After signing up, log in using the same credentials just to confirm that the account is working as expected and after that logout the account


Step 2: Use Punycode in Email & Re-Signup
We’re going to sign up again, but this time we’ll use Punycode characters inside the email address. You can use the script I created. it shows you all the available Punycode characters along with their encoded values. Just type in any alphabet you want to convert, and it’ll generate the Punycode for you.


scripts/punycode_gen.py at main · coffinxp/scripts
Contribute to coffinxp/scripts development by creating an account on GitHub.
github.com


You can see that I simply replaced the letter “a” in the email domain with “à” using a Punycode generator I created. You can also verify the result using any online Punycode decoder such as the Punycoder website.

Punycode converter (IDN converter)
A tool that converts a text with special characters (Unicode) to the Punycode encoding (just ASCII) and vice-versa…
www.punycoder.com


3: Intercept and Replace with Punycode in Burp
Here’s something important: browsers like Chrome automatically encode special characters, which will break this trick. So, you need to use Burp Suite to intercept the request and replace the email field manually with your Punycode version email like this and forward the request


Observe Duplicate Email Response
if the response says something like “Email already exists,” it means the application is treating both the original and Punycode email as the same after normalization. That’s a clear sign of misconfiguration and a potential vulnerability.


Step 4: Trigger Password Reset via Punycode Email
Now go to the “Forgot Password” or reset password page. Enter the Punycode version of the email address and again, do it through Burp Suite so the characters don’t get encoded

security@gmàil.com.bcrkly6yl8ke552nzjt7jtu52w8nwdk2.oastify.com


Step 5: Take Over the Account
Forward the request and now you should see an SMTP callback in Burp Collaborator with the password reset link. Copy that link, open it in your browser and reset the password.



Now, Try logging in again but this time with the original email, the non-Punycode one and the new password you just set.



And.. Boom you’re in. You’ve just taken over the account. Isn’t this one of the cleanest and most dangerous account takeover techniques you’ve seen? No user interaction, no phishing, no clicking links. just smart use of punycode email. That’s why this is considered a critical vulnerability and programs are paying such high bounties when it’s discovered on main website.

Advanced Method: Punycode in the Username Field
We’ve already explored how email normalization at the domain level can lead to account takeover. But what if the vulnerability exists in the username part of the email instead?

This method is even sneakier because most developers don’t sanitize the local-part of emails properly, especially when it involves Unicode characters.

How It Works:
Register this time using a Punycode-modified username like:
ṡecurity@gmail.com.bcrkly6yl8ke552nzjt7jtu52w8nwdk2.oastify.com
2. Again use Burp Suite to intercept and modify the request because browsers will encode Unicode characters by default.

3. If the server accepts this email and registers the account, that’s the first win.

4. Next, go to the “forgot password” form and this time input the non-Punycode version in user part:

security@gmail.com.bcrkly6yl8ke552nzjt7jtu52w8nwdk2.oastify.com
5. If you receive a reset email in Burp Collaborator, you’ve confirmed that the server is treating both as the same account.

After resetting the password via the received link, you’ll be able to log in using the original email. That’s a zero-click account takeover through the email’s local part and it’s just as impactful.

💡 2FA Bypass Tip: If site uses 2Fa and application mishandles email normalization (like treating gmáil.com as gmail.com), an attacker can register as victim@gmáil.com, set up 2FA and then use their own 2FA code to log into victim@gmail.com.

Ifyou don’t have Burp Suite Pro, you can use the Interactsh client instead — it works just as well and is much easier to use.


🏆 Subscriber Success: Bounty Earned!
After I dropped my Punycode ATO video, one of my subscribers found the same bug on a live target same day and landed $2.422 bounty and others subscriber are still in triage phase.


Mitigation: How Developers Can Prevent This
Enforce strict email validation
Only allow ASCII characters in email input fields (e.g., using regex or input sanitization libraries).
Normalize email addresses consistently
Convert Unicode to ASCII (e.g., using IDN.toASCII() or equivalent) and apply consistent normalization across all flows.
Block IDN and Punycode domains if not required
Reject emails containing Punycode-prefixed domains (like xn — example) unless your app supports international domains.
Apply consistent logic in signup, login, and reset flows
Make sure email validation and comparison use the same logic everywhere to avoid mismatches or bypasses.
Reference
If you want to dive deeper into how this vulnerability works under the hood including backend behavior and normalization details. I highly recommend checking out the in-depth article by the Voorivex team. They’ve done an excellent job breaking down the full technical flow.

Puny-Code Vulnerabilities & Account Takeover
Puny-code inconsistencies can enable account takeovers by exploiting character parsing vulnerabilities, affecting email…
blog.voorivex.team

You can also watch this video where I showed the complete practicle of this method:

Conclusion
Punycode-based IDN attacks are one of the most fascinating, underused and powerful account takeover tricks in modern bug bounty hunting. With the right tools and mindset, you can uncover serious vulnerabilities that many miss and earn huge bounties.

Upnext: If you found this helpful, you’ll definitely want to check out my article How One Path Traversal in Grafana Unleashed XSS, Open Redirect and SSRF (CVE-2025–4123). It’s a wild chain of exploits packed into a single vulnerability with PoCs and real impact 👇

How One Path Traversal in Grafana Unleashed XSS, Open Redirect and SSRF (CVE-2025–4123)
Abusing Client Path Traversal to Chain XSS, SSRF and Open Redirect in Grafana
infosecwriteups.com

Disclaimer
The content provided in this article is for educational and informational purposes only. Always ensure you have proper authorization before conducting security assessments. Use this information responsibly
