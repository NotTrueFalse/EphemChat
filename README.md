# EphemChat
This is the initialisation of a bigger project, I'm posting it here incase it get stollen by anyone and shared before me, just to say "I'm the author of it" if you prefer.

## Main idea
Two user share smal address|seed pair to each other to talk to each other, the goal is to make the discussion secure (resistant to replay attack / bruteforce / any sniffing technique) even if the server is compromised.
I created a veryy simple socket server, and very complexe client, so the security rely only on the client, so even if the server get comprised, client doesn't have to worry about their discussion getting leaked.

## OTV
OTV => One time verifier, used to know if you're actually talking to your contact or not; generated with a cryptographic and secure random algorithm (not sure about this one x) ).

## PS
Its still under construction, a weird bug make the random generator doesn't work, I'll find it and release the finished version when done.
Found any bug / Want to tell me to use RSA instead of some seed ? -> create a issue and try to convince me that there's something better than just a key and aes message wrapped with a OTV.

