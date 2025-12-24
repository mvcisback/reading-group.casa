## 1.1.0 (2025-12-24)

### Feat

- **nix**: Expose cli via nix flake.
- **api**: convert main to async
- **cli**: Colorization/prettification + show subcommand
- **cli**: Colorize outputs.
- **cli**: expand modify helpers
- **cli**: Sketch out basic cli interface.
- **ui**: drop /ui prefix for ui endpoints.
- **cli**: offer ui json responses

## 1.0.0 (2025-12-23)

### Feat

- **ui**: prefix html routes with /ui
- **security**: add token auth and rate limiting
- Support marking papers as covered.
- **ui**: Highlight the active navigation tab.
- Introduce ability to assign a presenter for each paper.
- Implement 404 page.
- **ui**: Remove unnecessary section tags and about page.
- **ui**: Seperate next paper from rest of queue.
- **ui**: Clean up transitions and make pages more minimal.
- Support archiving and deleting papers.
- **nix**: Support deploying using nix run.
- **Queue**: Switch to ranking via explict priority assignment.
- **UI**: Make the next paper sticky and trim down copy.
- **UI**: Create subpages and transitions between theme.
- Support scheduling multiple papers with specific dates.
- Add user logins for voting.
- Initial implementation.

### Fix

- Next paper part of queue in housekeeping.
- **ui**: Fall back to cross fading between pages using view transitions.
- Mutation endpoints now require log in.
