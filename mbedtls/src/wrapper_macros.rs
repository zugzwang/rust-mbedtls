/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

macro_rules! as_item {
    ($i:item) => {
        $i
    };
}

macro_rules! callback {
    //{ ($($arg:ident: $ty:ty),*) -> $ret:ty } => {
    //};
    { $n:ident$( : $sync:ident )*($($arg:ident: $ty:ty),*) -> $ret:ty } => {
        #[cfg(not(feature="threading"))]
        pub trait $n {
            unsafe extern "C" fn call(user_data: *mut ::mbedtls_sys::types::raw_types::c_void, $($arg:$ty),*) -> $ret where Self: Sized;

            fn data_ptr(&self) -> *mut ::mbedtls_sys::types::raw_types::c_void;
        }

        #[cfg(feature="threading")]
        pub trait $n $( : $sync )* {
            unsafe extern "C" fn call(user_data: *mut ::mbedtls_sys::types::raw_types::c_void, $($arg:$ty),*) -> $ret where Self: Sized;

            fn data_ptr(&self) -> *mut ::mbedtls_sys::types::raw_types::c_void;
        }

        #[cfg(not(feature="threading"))]
        impl<F> $n for F where F: Fn($($ty),*) -> $ret {
            unsafe extern "C" fn call(user_data: *mut ::mbedtls_sys::types::raw_types::c_void, $($arg:$ty),*) -> $ret where Self: Sized {
                (&mut*(user_data as *mut F))($($arg),*)
            }

            fn data_ptr(&self) -> *mut ::mbedtls_sys::types::raw_types::c_void {
                self as *mut F as *mut _
            }
        }

        #[cfg(feature="threading")]
        impl<F> $n for F where F: Sync + Fn($($ty),*) -> $ret {
            unsafe extern "C" fn call(user_data: *mut ::mbedtls_sys::types::raw_types::c_void, $($arg:$ty),*) -> $ret where Self: Sized {
                (&mut*(user_data as *mut F))($($arg),*)
            }

            fn data_ptr(&self) -> *mut ::mbedtls_sys::types::raw_types::c_void {
                self as *const F as *mut _
            }
        }
    };
    { $n:ident, $m:ident$( : $sync:ident )*($($arg:ident: $ty:ty),*) -> $ret:ty } => {
        #[cfg(not(feature="threading"))]
        pub unsafe trait $n {
            unsafe extern "C" fn call(user_data: *mut ::mbedtls_sys::types::raw_types::c_void, $($arg:$ty),*) -> $ret where Self: Sized;

            fn data_ptr_mut(&mut self) -> *mut ::mbedtls_sys::types::raw_types::c_void;
        }

        #[cfg(feature="threading")]
        pub unsafe trait $n $( : $sync )* {
            unsafe extern "C" fn call(user_data: *mut ::mbedtls_sys::types::raw_types::c_void, $($arg:$ty),*) -> $ret where Self: Sized;

            fn data_ptr_mut(&mut self) -> *mut ::mbedtls_sys::types::raw_types::c_void;
        }

        #[cfg(not(feature="threading"))]
        unsafe impl<F> $n for F where F: Fn($($ty),*) -> $ret {
            unsafe extern "C" fn call(user_data: *mut ::mbedtls_sys::types::raw_types::c_void, $($arg:$ty),*) -> $ret where Self: Sized {
                (&mut*(user_data as *mut F))($($arg),*)
            }

            fn data_ptr_mut(&mut self) -> *mut ::mbedtls_sys::types::raw_types::c_void {
                self as *mut F as *mut _
            }
        }

        #[cfg(feature="threading")]
        unsafe impl<F> $n for F where F: Sync + Fn($($ty),*) -> $ret {
            unsafe extern "C" fn call(user_data: *mut ::mbedtls_sys::types::raw_types::c_void, $($arg:$ty),*) -> $ret where Self: Sized {
                (&mut*(user_data as *mut F))($($arg),*)
            }

            fn data_ptr_mut(&mut self) -> *mut ::mbedtls_sys::types::raw_types::c_void {
                self as *const F as *mut _
            }
        }

        #[cfg(not(feature="threading"))]
        pub trait $m : $n {
            fn data_ptr(&self) -> *mut ::mbedtls_sys::types::raw_types::c_void;
        }

        #[cfg(feature="threading")]
        pub trait $m : $n $( + $sync )* {
            fn data_ptr(&self) -> *mut ::mbedtls_sys::types::raw_types::c_void;
        }

        #[cfg(not(feature="threading"))]
        impl<F> $m for F where F: $n + Fn($($ty),*) -> $ret {
            fn data_ptr(&self) -> *mut ::mbedtls_sys::types::raw_types::c_void {
                self as *mut F as *mut _
            }
        }

        #[cfg(feature="threading")]
        impl<F> $m for F where F: $n + Sync + Fn($($ty),*) -> $ret {
            fn data_ptr(&self) -> *mut ::mbedtls_sys::types::raw_types::c_void {
                self as *const F as *mut _
            }
        }
    };
}


macro_rules! define {
    { #[c_ty($inner:ident)] $(#[$m:meta])* struct $name:ident$(<$l:tt>)*; $($defs:tt)* } => {
        define_struct!(define $(#[$m])* struct $name $(lifetime $l)* inner $inner);
        define_struct!(<< $name $(lifetime $l)* inner $inner >> $($defs)*);
    };
    {                   #[c_ty($raw:ty)] $(#[$m:meta])* enum $n:ident { $(#[$doc:meta] $rust:ident = $c:ident,)* } } => { define_enum!(                  $(#[$m])* enum $n ty $raw : $(doc ($doc) rust $rust c $c),*); };
    {                   #[c_ty($raw:ty)] $(#[$m:meta])* enum $n:ident { $(             $rust:ident = $c:ident,)* } } => { define_enum!(                  $(#[$m])* enum $n ty $raw : $(doc (    ) rust $rust c $c),*); };
    { #[non_exhaustive] #[c_ty($raw:ty)] $(#[$m:meta])* enum $n:ident { $(#[$doc:meta] $rust:ident = $c:ident,)* } } => { define_enum!(#[non_exhaustive] $(#[$m])* enum $n ty $raw : $(doc ($doc) rust $rust c $c),*); };
    { #[non_exhaustive] #[c_ty($raw:ty)] $(#[$m:meta])* enum $n:ident { $(             $rust:ident = $c:ident,)* } } => { define_enum!(#[non_exhaustive] $(#[$m])* enum $n ty $raw : $(doc (    ) rust $rust c $c),*); };
}

macro_rules! define_enum {
    {#[non_exhaustive] $(#[$m:meta])* enum $n:ident ty $raw:ty : $(doc ($($doc:meta)*) rust $rust:ident c $c:ident),*} => {
        $(#[$m])*
        pub enum $n {
            $($(#[$doc])* $rust,)*
            // Stable-Rust equivalent of `#[non_exhaustive]` attribute. This
            // value should never be used by users of this crate!
            #[doc(hidden)]
            __Nonexhaustive,
        }

        impl Into<$raw> for $n {
            fn into(self) -> $raw {
                match self {
                    $($n::$rust => $c,)*
                    $n::__Nonexhaustive => unreachable!("__Nonexhaustive value should not be instantiated"),
                }
            }
        }
    };
    {$(#[$m:meta])* enum $n:ident ty $raw:ty : $(doc ($($doc:meta)*) rust $rust:ident c $c:ident),*} => {
        $(#[$m])*
        pub enum $n {
            $($(#[$doc])* $rust,)*
        }

        impl Into<$raw> for $n {
            fn into(self) -> $raw {
                match self {
                    $($n::$rust => $c,)*
                }
            }
        }
    };
}

macro_rules! define_struct {
    { define $(#[$m:meta])* struct $name:ident $(lifetime $l:tt)* inner $inner:ident } => {
        as_item!(
        #[allow(dead_code)]
        $(#[$m])*
        pub struct $name<$($l)*> {
            inner: ::mbedtls_sys::$inner,
            $(r: ::core::marker::PhantomData<&$l ()>,)*
        }
        );

        as_item!(
        #[allow(dead_code)]
        impl<$($l)*> $name<$($l)*> {
            pub(crate) fn into_inner(self) -> ::mbedtls_sys::$inner {
                let inner = self.inner;
                ::core::mem::forget(self);
                inner
            }

            pub(crate) fn handle(&self) -> &::mbedtls_sys::$inner {
                &self.inner
            }

            pub(crate) fn handle_mut(&mut self) -> &mut ::mbedtls_sys::$inner {
                &mut self.inner
            }
        }
        );

        as_item!(
        #[cfg(feature="threading")]
        unsafe impl<$($l)*> Send for $name<$($l)*> {}
        );
    };

    { << $name:ident $(lifetime $l:tt)* inner $inner:ident >> const init: fn() -> Self = $ctor:ident; $($defs:tt)* } => {
        define_struct!(init $name () init $ctor $(lifetime $l)* );
        define_struct!(<< $name $(lifetime $l)* inner $inner >> $($defs)*);
    };
    { << $name:ident $(lifetime $l:tt)* inner $inner:ident >> pub const new: fn() -> Self = $ctor:ident; $($defs:tt)* } => {
        define_struct!(init $name (pub) new $ctor $(lifetime $l)* );
        define_struct!(<< $name $(lifetime $l)* inner $inner >> $($defs)*);
    };
    { init $name:ident ($($vis:tt)*) $new:ident $ctor:ident $(lifetime $l:tt)* } => {
        as_item!(
        #[allow(dead_code)]
        impl<$($l)*> $name<$($l)*> {
            $($vis)* fn $new() -> Self {
                let mut inner = ::core::mem::MaybeUninit::uninit();
                let inner = unsafe {
                    ::mbedtls_sys::$ctor(inner.as_mut_ptr());
                    inner.assume_init()
                };
                $name{
                    inner:inner,
                    $(r: ::core::marker::PhantomData::<&$l _>,)*
                }
            }
        }
        );
    };

    { << $name:ident $(lifetime $l:tt)* inner $inner:ident >> const drop: fn(&mut Self) = $dtor:ident; $($defs:tt)* } => {
        define_struct!(drop $name dtor $dtor $(lifetime $l)* );
        define_struct!(<< $name $(lifetime $l)* inner $inner >> $($defs)*);
    };
    { drop $name:ident dtor $dtor:ident $(lifetime $l:tt)* } => {
        as_item!(
        impl<$($l)*> Drop for $name<$($l)*> {
            fn drop(&mut self) {
                unsafe{::mbedtls_sys::$dtor(&mut self.inner)};
            }
        }
        );
    };

    { << $name:ident $(lifetime $l:tt)* inner $inner:ident >> impl<$l2:tt> Into<ptr> {} $($defs:tt)* } => {
        define_struct!(into $name inner $inner $(lifetime $l)* lifetime2 $l2 );
        define_struct!(<< $name $(lifetime $l)* inner $inner >> $($defs)*);
    };
    { into $name:ident inner $inner:ident $(lifetime $l:tt)* lifetime2 $l2:tt } => {
        as_item!(
        impl<$l2,$($l),*> Into<*const $inner> for &$l2 $name<$($l)*> {
            fn into(self) -> *const $inner {
                &self.inner
            }
        }
        );

        as_item!(
        impl<$l2,$($l),*> Into<*mut $inner> for &$l2 mut $name<$($l)*> {
            fn into(self) -> *mut $inner {
                &mut self.inner
            }
        }
        );
    };

    { << $name:ident $(lifetime $l:tt)* inner $inner:ident >> impl<$l2:tt> UnsafeFrom<ptr> {} $($defs:tt)* } => {
        define_struct!(unsafe_from $name inner $inner $(lifetime $l)* lifetime2 $l2 );
        define_struct!(<< $name $(lifetime $l)* inner $inner >> $($defs)*);
    };
    { unsafe_from $name:ident inner $inner:ident $(lifetime $l:tt)* lifetime2 $l2:tt } => {
        as_item!(
        impl<$l2,$($l),*> crate::private::UnsafeFrom<*const $inner> for &$l2 $name<$($l)*> {
            unsafe fn from(ptr: *const $inner) -> Option<Self> {
                (ptr as *const $name).as_ref()
            }
        }
        );

        as_item!(
        impl<$l2,$($l),*> crate::private::UnsafeFrom<*mut $inner> for &$l2 mut $name<$($l)*> {
            unsafe fn from(ptr: *mut $inner) -> Option<Self> {
                (ptr as *mut $name).as_mut()
            }
        }
        );
    };

    { << $name:ident $(lifetime $l:tt)* inner $inner:ident >> } => {};
    { lifetime $l:tt } => {};
}
