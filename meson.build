# Rules for building with Meson

project(
    'aladdin-2fa',
    'cpp',
    default_options: [
        'cpp_std=c++20',
        'warning_level=3',
        'buildtype=release',
    ],
    license: 'MIT',
    version: 'devel',
    meson_version: '>=1.1',
)

# version info
version = get_option('version')
if version == 'devel'
    git = find_program('git', native: true, required: false)
    if git.found()
        git_ver = run_command(
            [git, 'describe', '--tags', '--long', '--always', '--dirty'],
            check: false,
        )
        if git_ver.returncode() == 0
            version = git_ver.stdout().strip().substring(1)
        endif
    endif
endif
add_project_arguments(['-DVERSION="' + version + '"'], language: 'cpp')

executable(
    'aladdin-2fa',
    [
        'src/main.cpp',
        'src/totp.cpp',
        'src/decode.cpp',
    ],
    include_directories: 'include',
    dependencies: [dependency('libssl'), dependency('libcrypto')],
    install: true,
)
