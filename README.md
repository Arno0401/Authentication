### create middleware for checking token ✔
### create middleware for checking role for admins ✔
### create route for only admins (if role != admin respond 403)✔
### error response function as json (in utils) ✔
### parse token function ✔
### http.Handle("/users", adminMW(handler.GetUsers)) // route for only admins✔
