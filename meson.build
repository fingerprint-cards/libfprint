project('libfprint', [ 'c', 'cpp' ],
    version: '1.90.7',
    license: 'LGPLv2.1+',
    default_options: [
        'buildtype=debugoptimized',
        'warning_level=1',
        'c_std=gnu99',
    ],
    meson_version: '>= 0.49.0')

gnome = import('gnome')

libfprint_conf = configuration_data()

cc = meson.get_compiler('c')
cpp = meson.get_compiler('cpp')
host_system = host_machine.system()
glib_min_version = '2.56'

glib_version_def = 'GLIB_VERSION_@0@_@1@'.format(
    glib_min_version.split('.')[0], glib_min_version.split('.')[1])
common_cflags = cc.get_supported_arguments([
    '-Wall',
    '-Wcast-align',
    '-Wformat-nonliteral',
    '-Wformat-security',
    '-Wformat=2',
    '-Wignored-qualifiers',
    '-Wlogical-op',
    '-Wmissing-declarations',
    '-Wmissing-format-attribute',
    '-Wmissing-include-dirs',
    '-Wmissing-noreturn',
    '-Wpointer-arith',
    '-Wshadow',
    '-Wtype-limits',
    '-Wundef',
    '-Wunused',
    '-Werror=address',
    '-Werror=array-bounds',
    '-Werror=empty-body',
    '-Werror=init-self',
    '-Werror=int-to-pointer-cast',
    '-Werror=main',
    '-Werror=missing-braces',
    '-Werror=nonnull',
    '-Werror=redundant-decls',
    '-Werror=return-type',
    '-Werror=sequence-point',
    '-Werror=trigraphs',
    '-Werror=write-strings',
    '-fno-strict-aliasing',
    '-DGLIB_VERSION_MIN_REQUIRED=' + glib_version_def,
    '-DGLIB_VERSION_MAX_ALLOWED=' + glib_version_def,
    '-D_GNU_SOURCE',
    '-DG_LOG_DOMAIN="@0@"'.format(meson.project_name()),
])
c_cflags = cc.get_supported_arguments([
    '-Wimplicit-function-declaration',
    '-Wmissing-prototypes',
    '-Wnested-externs',
    '-Wold-style-definition',
    '-Wstrict-prototypes',
    '-Werror=implicit',
    '-Werror=pointer-to-int-cast',
])
add_project_arguments(common_cflags + c_cflags, language: 'c')
add_project_arguments(common_cflags, language: 'cpp')

# maintaining compatibility with the previous libtool versioning
# current = binary - interface
# revision = interface
soversion = 2
current = 0
revision = 0
libversion = '@0@.@1@.@2@'.format(soversion, current, revision)
versioned_libname = meson.project_name() + '-' + soversion.to_string()

# Dependencies
glib_dep = dependency('glib-2.0', version: '>=' + glib_min_version)
gio_dep = dependency('gio-unix-2.0', version: '>=' + glib_min_version)
gobject_dep = dependency('gobject-2.0', version: '>=' + glib_min_version)
gusb_dep = dependency('gusb', version: '>= 0.2.0')
mathlib_dep = cc.find_library('m', required: false)

# The following dependencies are only used for tests
cairo_dep = dependency('cairo', required: false)

# Drivers
drivers = get_option('drivers').split(',')
virtual_drivers = [
    'virtual_image',
    'virtual_device',
    'virtual_device_storage',
    'virtual_sdcp',
]
default_drivers = [
    'upektc_img',
    'vfs5011',
    'aes3500',
    'aes4000',
    'aes1610',
    'aes1660',
    'aes2660',
    'aes2501',
    'aes2550',
    'vfs101',
    'vfs301',
    'vfs0050',
    'etes603',
    'vcom5s',
    'synaptics',
    'elan',
    'uru4000',
    'upektc',
    'upeksonly',
    'upekts',
    'goodixmoc',
]

# FIXME: All the drivers should be fixed by adjusting the byte order.
# See https://gitlab.freedesktop.org/libfprint/libfprint/-/issues/236
endian_independent_drivers = virtual_drivers + [
    'aes3500',
    'synaptics',
]

all_drivers = default_drivers + virtual_drivers

if drivers == [ 'all' ]
    drivers = all_drivers
endif

if drivers == [ 'default' ]
    drivers = default_drivers
endif

if drivers.length() == 0 or drivers[0] == ''
    error('Cannot build libfprint without drivers, please specify a valid value for the drivers option')
endif

if drivers == all_drivers or drivers == default_drivers
    default_drivers_are_enabled = true
else
    default_drivers_are_enabled = true
    foreach driver: default_drivers
        if driver not in drivers
            default_drivers_are_enabled = false
            break
        endif
    endforeach
endif

supported_drivers = []
foreach driver: drivers
    if build_machine.endian() == 'little' or driver in endian_independent_drivers
        supported_drivers += driver
    else
        warning('Driver @0@ is not supported by big endian cpu @1@. Please, fix it!'.format(
            driver, build_machine.cpu()))
    endif
endforeach

if default_drivers_are_enabled and supported_drivers != drivers
    default_drivers_are_enabled = false
endif

root_inc = include_directories('.')

if get_option('udev_rules')
    udev_hwdb_dir = get_option('udev_hwdb_dir')

    if udev_hwdb_dir == 'auto'
        udev_dep = dependency('udev')
        udev_hwdb_dir = udev_dep.get_pkgconfig_variable('udevdir') + '/hwdb.d'
    endif
else
    udev_hwdb_dir = false
endif

if get_option('gtk-examples')
    gnome = import('gnome')

    gtk_dep = dependency('gtk+-3.0', required: false)
    if not gtk_dep.found()
        error('GTK+ 3.x is required for GTK+ examples')
    endif
endif

# Some dependency resolving happens inside here
subdir('libfprint')

configure_file(output: 'config.h', configuration: libfprint_conf)

subdir('examples')
if get_option('doc')
    gnome = import('gnome')
    subdir('doc')
endif
if get_option('gtk-examples')
    subdir('demo')
endif

subdir('data')
subdir('tests')

pkgconfig = import('pkgconfig')
pkgconfig.generate(
    name: versioned_libname,
    description: 'Generic C API for fingerprint reader access',
    version: meson.project_version(),
    libraries: libfprint,
    requires: [gio_dep, gobject_dep],
    subdirs: versioned_libname,
    filebase: versioned_libname,
)
