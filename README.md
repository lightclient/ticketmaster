# TicketMaster

_an eth prague 2023 submission_

The `ticketmaster` is a coordinator that allows users to purchase "tickets"
that can later be "redeemed" to fund a [stealth account][1]. The mechanism uses
blind signatures so the coordinator is unable to link individual tickets with
redeemers. It is an implementation of Toni Wahrstätter's post ["Fee
Ticketing"][2].

![this is fine](https://github.com/nerolation/Ethereum-ticket-system/assets/51536394/a509950b-d5dd-4093-8995-572e9cb8081e)

[1]: https://vitalik.ca/general/2023/01/20/stealth.html
[2]: https://hackmd.io/@Nerolation/rkp8LyRUh
