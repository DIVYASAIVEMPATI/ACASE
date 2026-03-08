MAX_REPEATS = 2
FORBIDDEN_REPEAT = {"CONTROLLED_SPRAY"}
REQUIRES_PRECONDITION = {
    "CONTROLLED_SPRAY": "ENUM_USER",
    "TEST_RESET": "ENUM_USER",
}

def validate_action(action, history, observation):
    if action in FORBIDDEN_REPEAT and action in history:
        print(f"[Guard] Blocked repeat of: {action}")
        return "STOP"
    if history.count(action) >= MAX_REPEATS:
        print(f"[Guard] {action} repeated too many times - stopping.")
        return "STOP"
    if action in REQUIRES_PRECONDITION:
        required = REQUIRES_PRECONDITION[action]
        if required not in history:
            print(f"[Guard] {action} requires {required} first.")
            return required
    return action
