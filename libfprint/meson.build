libfprint_sources = [
    'fp-context.c',
    'fp-device.c',
    'fp-image.c',
    'fp-print.c',
    'fp-image-device.c',
]

libfprint_private_sources = [
    'fpi-assembling.c',
    'fpi-byte-reader.c',
    'fpi-byte-writer.c',
    'fpi-device.c',
    'fpi-image-device.c',
    'fpi-image.c',
    'fpi-print.c',
    'fpi-ssm.c',
    'fpi-usb-transfer.c',
]

libfprint_public_headers = [
    'fp-context.h',
    'fp-device.h',
    'fp-image-device.h',
    'fp-image.h',
    'fp-print.h',
]

libfprint_private_headers = [
    'fpi-assembling.h',
    'fpi-byte-reader.h',
    'fpi-byte-utils.h',
    'fpi-byte-writer.h',
    'fpi-compat.h',
    'fpi-context.h',
    'fpi-device.h',
    'fpi-image-device.h',
    'fpi-image.h',
    'fpi-log.h',
    'fpi-minutiae.h',
    'fpi-print.h',
    'fpi-usb-transfer.h',
    'fpi-ssm.h',
]

nbis_sources = [
    'nbis/bozorth3/bozorth3.c',
    'nbis/bozorth3/bz_alloc.c',
    'nbis/bozorth3/bz_drvrs.c',
    'nbis/bozorth3/bz_gbls.c',
    'nbis/bozorth3/bz_io.c',
    'nbis/bozorth3/bz_sort.c',
    'nbis/mindtct/binar.c',
    'nbis/mindtct/block.c',
    'nbis/mindtct/chaincod.c',
    'nbis/mindtct/contour.c',
    'nbis/mindtct/detect.c',
    'nbis/mindtct/dft.c',
    'nbis/mindtct/free.c',
    'nbis/mindtct/getmin.c',
    'nbis/mindtct/globals.c',
    'nbis/mindtct/imgutil.c',
    'nbis/mindtct/init.c',
    'nbis/mindtct/line.c',
    'nbis/mindtct/link.c',
    'nbis/mindtct/log.c',
    'nbis/mindtct/loop.c',
    'nbis/mindtct/maps.c',
    'nbis/mindtct/matchpat.c',
    'nbis/mindtct/minutia.c',
    'nbis/mindtct/morph.c',
    'nbis/mindtct/quality.c',
    'nbis/mindtct/remove.c',
    'nbis/mindtct/ridges.c',
    'nbis/mindtct/shape.c',
    'nbis/mindtct/sort.c',
    'nbis/mindtct/util.c',
    'nbis/mindtct/xytreps.c',
]

driver_sources = {
    'upekts' :
        [ 'drivers/upekts.c', 'drivers/upek_proto.c' ],
    'upektc' :
        [ 'drivers/upektc.c' ],
    'upeksonly' :
        [ 'drivers/upeksonly.c' ],
    'uru4000' :
        [ 'drivers/uru4000.c' ],
    'aes1610' :
        [ 'drivers/aes1610.c' ],
    'aes1660' :
        [ 'drivers/aes1660.c' ],
    'aes2501' :
        [ 'drivers/aes2501.c' ],
    'aes2550' :
        [ 'drivers/aes2550.c' ],
    'aes2660' :
        [ 'drivers/aes2660.c' ],
    'aes3500' :
        [ 'drivers/aes3500.c' ],
    'aes4000' :
        [ 'drivers/aes4000.c' ],
    'vcom5s' :
        [ 'drivers/vcom5s.c' ],
    'vfs101' :
        [ 'drivers/vfs101.c' ],
    'vfs301' :
        [ 'drivers/vfs301.c', 'drivers/vfs301_proto.c' ],
    'vfs5011' :
        [ 'drivers/vfs5011.c' ],
    'upektc_img' :
        [ 'drivers/upektc_img.c',  'drivers/upek_proto.c' ],
    'etes603' :
        [ 'drivers/etes603.c' ],
    'vfs0050' :
        [ 'drivers/vfs0050.c' ],
    'elan' :
        [ 'drivers/elan.c' ],
    'virtual_image' :
        [ 'drivers/virtual-image.c' ],
    'virtual_device' :
        [ 'drivers/virtual-device.c' ],
    'virtual_device_storage' :
        [ 'drivers/virtual-device-storage.c' ],
    'virtual_sdcp' :
        [ 'drivers/virtual-sdcp.c' ],
    'synaptics' :
        [ 'drivers/synaptics/synaptics.c', 'drivers/synaptics/bmkt_message.c' ],
    'goodixmoc' :
        [ 'drivers/goodixmoc/goodix.c', 'drivers/goodixmoc/goodix_proto.c' ],
}

helper_sources = {
    'sdcp' :
        [ 'fp-sdcp-device.c', 'fpi-sdcp-device.c' ],
    'aeslib' :
        [ 'drivers/aeslib.c' ],
    'aesx660' :
        [ 'drivers/aesx660.c' ],
    'aes3k' :
        [ 'drivers/aes3k.c' ],
    'virtual' :
        [ 'drivers/virtual-device-listener.c' ],
}

driver_helpers = {
    'aes1610' : [ 'aeslib' ],
    'aes1660' : [ 'aeslib', 'aesx660' ],
    'aes2501' : [ 'aeslib' ],
    'aes2550' : [ 'aeslib' ],
    'aes2660' : [ 'aeslib', 'aesx660' ],
    'aes3500' : [ 'aeslib', 'aes3k' ],
    'aes4000' : [ 'aeslib', 'aes3k' ],
    'virtual_image'          : [ 'virtual' ],
    'virtual_device'         : [ 'virtual' ],
    'virtual_device_storage' : [ 'virtual' ],
    'virtual_sdcp' : [ 'sdcp' ],
}

helpers = []
foreach driver : drivers
    if driver in driver_helpers
        foreach helper : driver_helpers[driver]
            if helper not in helpers
                helpers += helper
            endif
        endforeach
    endif
endforeach

drivers_sources = []
drivers_cflags = []
foreach driver: drivers
    drivers_sources += driver_sources[driver]
endforeach
foreach helper : helpers
    drivers_sources += helper_sources[helper]
endforeach

optional_deps = []

# Resolve extra dependencies
foreach i : helpers + drivers
    driver = i
    foreach d, helper : driver_helpers
        if i in helpers
            driver = d
            break
        endif
    endforeach

    if i == 'aes3k'
        imaging_dep = dependency('pixman-1', required: false)
        if not imaging_dep.found()
            error('pixman is required for @0@ and possibly others'.format(driver))
        endif

        libfprint_conf.set10('HAVE_PIXMAN', true)
        optional_deps += imaging_dep
    elif i == 'uru4000'
        nss_dep = dependency('nss', required: false)
        if not nss_dep.found()
            error('nss is required for uru4000')
        endif

        optional_deps += nss_dep
    elif i == 'sdcp'
        nss_dep = dependency('nss', version: '>=3.55', required: false)
        if not nss_dep.found()
            error('nss >=3.55 is required for SDCP support (@0@ and possibly others)'.format(driver))
        endif

        optional_deps += nss_dep
    else
       deps = []
       continue
    endif

endforeach

fp_enums = gnome.mkenums_simple('fp-enums',
    sources: libfprint_public_headers,
    install_header: true,
    install_dir: get_option('includedir') / versioned_libname,
)
fp_enums_h = fp_enums[1]

fpi_enums = gnome.mkenums_simple('fpi-enums',
    sources: libfprint_private_headers,
    install_header: false,
)
fpi_enums_h = fpi_enums[1]

enums_dep = declare_dependency(
    sources: [ fp_enums_h, fpi_enums_h ]
)

# Export the drivers' types to the core code
drivers_type_list = []
drivers_type_func = []
drivers_type_list += '#include <glib-object.h>'
drivers_type_list += '#include "fpi-context.h"'
drivers_type_list += ''
drivers_type_func += 'GArray *'
drivers_type_func += 'fpi_get_driver_types (void)'
drivers_type_func += '{'
drivers_type_func += '  GArray *drivers = g_array_new (TRUE, FALSE, sizeof (GType));'
drivers_type_func += '  GType t;'
drivers_type_func += ''
foreach driver: supported_drivers
    drivers_type_list += 'extern GType (fpi_device_' + driver + '_get_type) (void);'
    drivers_type_func += '  t = fpi_device_' + driver + '_get_type ();'
    drivers_type_func += '  g_array_append_val (drivers, t);'
    drivers_type_func += ''
endforeach
drivers_type_list += ''
drivers_type_func += '  return drivers;'
drivers_type_func += '}'

drivers_sources += configure_file(input: 'empty_file',
    output: 'fpi-drivers.c',
    capture: true,
    command: [
        'echo',
        '\n'.join(drivers_type_list + [] + drivers_type_func)
    ])

deps = [
    enums_dep,
    gio_dep,
    glib_dep,
    gobject_dep,
    gusb_dep,
    mathlib_dep,
] + optional_deps

# These are empty and only exist so that the include directories are created
# in the build tree. This silences a build time warning.
subdir('nbis/include')
subdir('nbis/libfprint-include')
deps += declare_dependency(include_directories: [
    root_inc,
    include_directories('nbis/include'),
    include_directories('nbis/libfprint-include'),
])

libnbis = static_library('nbis',
    nbis_sources,
    dependencies: deps,
    c_args: cc.get_supported_arguments([
        '-Wno-error=redundant-decls',
        '-Wno-redundant-decls',
        '-Wno-discarded-qualifiers',
        '-Wno-array-bounds',
        '-Wno-array-parameter',
    ]),
    install: false)

libfprint_private = static_library('fprint-private',
    sources: [
        fpi_enums,
        libfprint_private_sources,
    ],
    dependencies: deps,
    link_with: libnbis,
    install: false)

libfprint_drivers = static_library('fprint-drivers',
    sources: drivers_sources,
    c_args: drivers_cflags,
    dependencies: deps,
    link_with: libfprint_private,
    install: false)

mapfile = files('libfprint.ver')
vflag = '-Wl,--version-script,@0@/@1@'.format(meson.source_root(), mapfile[0])

libfprint = shared_library(versioned_libname.split('lib')[1],
    sources: [
        fp_enums,
        libfprint_sources,
    ],
    soversion: soversion,
    version: libversion,
    link_args : vflag,
    link_depends : mapfile,
    link_with: [libfprint_drivers, libfprint_private],
    dependencies: deps,
    install: true)

libfprint_dep = declare_dependency(link_with: libfprint,
    include_directories: root_inc,
    dependencies: [
        enums_dep,
        gio_dep,
        glib_dep,
        gobject_dep,
        gusb_dep,
    ])

install_headers(['fprint.h'] + libfprint_public_headers,
    subdir: versioned_libname
)

libfprint_private_dep = declare_dependency(
    include_directories: include_directories('.'),
    link_with: libfprint_private,
    dependencies: [
        deps,
        libfprint_dep,
    ]
)

udev_hwdb = executable('fprint-list-udev-hwdb',
    'fprint-list-udev-hwdb.c',
    dependencies: libfprint_private_dep,
    link_with: libfprint_drivers,
    install: false)

udev_hwdb_generator = custom_target('udev-hwdb',
    output: 'autosuspend.hwdb',
    depend_files: drivers_sources,
    capture: true,
    command: [ udev_hwdb ],
    install: false,
)

custom_target('sync-udev-hwdb',
    depends: udev_hwdb_generator,
    output: 'sync-udev-hwdb',
    install: false,
    command: [
        'cp', '-v',
        udev_hwdb_generator.full_path(),
        meson.source_root() / 'data'
    ]
)

supported_devices = executable('fprint-list-supported-devices',
    'fprint-list-supported-devices.c',
    dependencies: libfprint_private_dep,
    link_with: libfprint_drivers,
    install: false)


if get_option('introspection')
    # We do *not* include the private header here
    libfprint_girtarget = gnome.generate_gir(libfprint,
        sources : fp_enums + [
            libfprint_public_headers,
            libfprint_sources,
        ],
        nsversion : '@0@.0'.format(soversion),
        namespace : 'FPrint',
        symbol_prefix : 'fp_',
        identifier_prefix : 'Fp',
        export_packages : 'fprint',
        extra_args : [
            '--c-include=fprint.h',
        ],
        link_with : libfprint,
        dependencies : [
            gio_dep,
            gobject_dep,
            gusb_dep,
        ],
        includes : [
            'Gio-2.0',
            'GObject-2.0',
            'GUsb-1.0',
        ],
        install : true)
    libfprint_gir = libfprint_girtarget[0]
    libfprint_typelib = libfprint_girtarget[1]
endif
