# AuthKit API

![CI](https://github.com/peacedayou/authkit-api/actions/workflows/ci.yml/badge.svg)

Service d'authentification **ASP.NET Core (.NET 10)** prêt à brancher sur une application :
inscription, connexion, jetons JWT de courte durée, jetons de rafraîchissement avec rotation,
rôles et administration. Chaque mesure de sécurité est couverte par un test d'intégration.

## Points d'accès

| Méthode | Route | Rôle |
| --- | --- | --- |
| POST | `/auth/register` | Créer un compte (mot de passe de 12 caractères ou plus, avec majuscule, minuscule et chiffre) |
| POST | `/auth/login` | Obtenir un jeton d'accès (15 min) et un jeton de rafraîchissement (7 jours) |
| POST | `/auth/refresh` | Nouveau couple de jetons ; l'ancien jeton de rafraîchissement est révoqué |
| POST | `/auth/logout` | Révoque la session |
| GET | `/me` | Profil de l'utilisateur connecté |
| GET | `/admin/users` | Liste des utilisateurs (rôle Admin) |
| PUT | `/admin/users/{id}/roles` | Modifier les rôles (rôle Admin) |

## Sécurité

| Menace | Protection | Test |
| --- | --- | --- |
| Vol de la base de données | Mots de passe hachés PBKDF2 (ASP.NET Core Identity), jetons de rafraîchissement stockés sous forme d'empreinte SHA-256 | `Password_is_never_stored_in_clear` |
| Devinette de mots de passe | Verrouillage de 15 min après 5 échecs, limite de 10 requêtes par minute et par adresse IP | `Account_locks_…`, `Too_many_login_attempts_return_429` |
| Découverte des comptes | Même réponse et temps comparable, que le compte existe ou non | `Wrong_password_and_unknown_user_…` |
| Vol d'un jeton de rafraîchissement | Rotation à chaque usage ; la réutilisation d'un ancien jeton révoque toute la session | `Reusing_an_old_refresh_token_…` |
| Jetons falsifiés | Signature HMAC-SHA256 vérifiée, émetteur, audience et durée contrôlés, algorithme imposé | `Invalid_or_missing_token_is_rejected` |
| Escalade de privilèges | Routes d'administration réservées au rôle Admin, liste blanche de rôles | `Admin_routes_require_admin_role`, `Unknown_role_is_rejected` |
| Secrets dans le code | Clé JWT et administrateur initial lus dans la configuration ; l'application refuse de démarrer sans clé de 32 caractères | – |

## Démarrage

```bash
export Jwt__Key="$(openssl rand -base64 48)"
export Admin__Email="admin@exemple.com" Admin__Password="Un-Mot-De-Passe-Solide-2026"
dotnet run --project src/AuthKit.Api      # Swagger sur /swagger en développement
dotnet test tests/AuthKit.Api.Tests
```

## Pistes d'amélioration

Confirmation du courriel et réinitialisation du mot de passe, double authentification TOTP,
connexion par passkeys (WebAuthn), PostgreSQL avec migrations, journal d'audit.

## Technologies

C# · .NET 10 · ASP.NET Core Minimal APIs · JWT · Entity Framework Core · SQLite · xUnit · GitHub Actions
