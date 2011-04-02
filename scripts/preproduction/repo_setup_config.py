repoSetupConfig = {}
repoSetupConfig['hgHost'] = 'hg.mozilla.org'
repoSetupConfig['repoPath'] = 'users/prepr-ffxbld'
repoSetupConfig['hgUserName'] = 'prepr-ffxbld'
repoSetupConfig['hgSshKey'] = 'ffxbld_dsa'

repoSetupConfig['reposToClone'] = {
    'build/buildbot-configs': {
        'overrides': {
            'mozilla/release-firefox-mozilla-1.9.1.py': [
                'mozilla/preproduction_release_overrides.py',
                'mozilla/preproduction_release_overrides-1.9.1.py',
             ],
            'mozilla/release-firefox-mozilla-1.9.2.py': [
                'mozilla/preproduction_release_overrides.py',
                'mozilla/preproduction_release_overrides-1.9.2.py',
             ],
            'mozilla/release-firefox-mozilla-2.0.py': [
                'mozilla/preproduction_release_overrides.py',
                'mozilla/preproduction_release_overrides-2.0.py',
             ],
        },
        'doTag': True,
    },
    'build/tools': {
        'doTag': True,
    },
    'build/buildbotcustom': {},
    'build/buildbot': {},
}
