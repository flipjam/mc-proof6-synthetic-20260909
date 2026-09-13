"""One forbidden slot per case; no real credential values."""
BASE = 'f0fab30f43954340def4f46ac9fff1fdc3ec5afd'
TOKEN = 'PROOF6_D04_STATUS_TOKEN'
SLOTS = {
    'helper': ('GITHUB_TOKEN', 'GH_TOKEN', 'PROOF6_APP_TOKEN', 'PROOF6_APP_PRIVATE_KEY', 'PROOF6_NEW_API_TOKEN'),
    'setup-helper': ('GITHUB_TOKEN', 'GH_TOKEN', 'PROOF6_APP_TOKEN', 'PROOF6_APP_PRIVATE_KEY', 'PROOF6_NEW_API_TOKEN'),
    'setup-peer': ('GITHUB_TOKEN', 'GH_TOKEN', 'PROOF6_APP_TOKEN', 'PROOF6_APP_PRIVATE_KEY', 'PROOF6_NEW_API_TOKEN', TOKEN),
    'writer': ('GITHUB_TOKEN', 'GH_TOKEN', 'PROOF6_APP_PRIVATE_KEY', 'PROOF6_NEW_API_TOKEN', TOKEN),
}
CASES = [(role, slot, value) for role, slots in SLOTS.items() for slot in slots
         for value in ('INERT_FORBIDDEN_VALUE', '')]


def environment(public, role):
    if role in ('helper', 'setup-helper'):
        return public | {TOKEN: 'STATUS_SENTINEL'}
    if role == 'writer':
        return public | {'PROOF6_APP_TOKEN': 'APP_SENTINEL'}
    return dict(public)


def label(role, slot, value):
    return role.replace('-', '_') + '_' + slot + ('_nonempty' if value else '_empty')
