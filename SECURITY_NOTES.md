# Security baseline – 2026-11-03

- Anonymous `GET /recipes` → returns all recipes, including non-public ones (e.g. "Secret family hot sauce" with `is_public: false`).
- Anonymous `POST /recipes` → creates a new recipe (e.g. "Evil test recipe") and it is stored in the database.
- Anonymous `DELETE /recipes/4` → successfully deletes the previously created "Evil test recipe".