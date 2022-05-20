import pytest
from jhub_remote_user_authenticator import remote_user_auth


@pytest.mark.parametrize('authclass',
                         [remote_user_auth.RemoteUserAuthenticator,
                          remote_user_auth.RemoteUserLocalAuthenticator])
def test_valid_organization(authclass):
    auth = authclass()
    auth.openidp_allow_patterns = [r'^.+\.(ac|go)\.jp$', r'^.+[@.]domain1\.jp$']
    assert not auth.check_valid_organization({})
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test-org.co.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test-org.com',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@go.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@ac.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test-org.ac.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'test@test-org.ac.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test-org.go.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'test@test-org.go.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@domain1.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test.domain1.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test@test.domain1.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': '"dangerous-local://part////."@test.domain1.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'not@valid@test.go.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': '"dangerous-localpart"@test.go.jp',
    })

    auth.openidp_allow_patterns = [r'^.*\@(.+\.)?newdomain\.jp$']
    assert not auth.check_valid_organization({})
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test-org.co.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test-org.com',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@go.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@ac.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test-org.ac.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'test@test-org.ac.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test-org.go.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'test@test-org.go.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@domain1.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@newdomain.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test.newdomain.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test@test.newdomain.jp',
    })
    assert not auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': '"dangerous-local://part////."@test.newdomain.jp',
    })

    auth.allow_any_organizations = True
    assert auth.check_valid_organization({})
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test-org.co.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test-org.com',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@go.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@ac.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test-org.ac.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'test@test-org.ac.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test-org.go.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'test@test-org.go.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@domain1.jp',
    })
    assert auth.check_valid_organization({
        'Eppn': 'testtest@openidp.nii.ac.jp',
        'Mail': 'test@test.domain1.jp',
    })
