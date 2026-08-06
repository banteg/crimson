# Grim pixel-format scalar-deleting destructors

VC6 emits one scalar-deleting destructor for each polymorphic pixel-format
class. The five helpers in this family all call the class destructor, test bit
zero of the compiler-supplied flags, conditionally invoke `operator delete`,
and return `this`. Three qualified destructor forwarders also reproduce the
adjacent one-instruction jump thunks. Together the family accounts for 155
exact bytes in the explicit `all` matching scope.

The scaffold defines a constructor so VC6 instantiates each vtable and its
scalar-deleting helper, while deliberately leaving the ordinary destructor
undefined. Each scratch maps that unresolved destructor relocation to the
specific native destructor or jump thunk observed at the corresponding target.
This preserves the real compiler-generated helper shape without replacing the
destructor dependency with a handwritten stand-in.

The forwarders use qualified destructor calls so the compiler emits a direct
tail jump instead of dispatching through the vtable. Their relocations are
likewise checked against the concrete native destructors.

All five helpers are exact with the same VC6 SP6 `/O1 /G6 /W3 /GR- /MD`
profile recovered from the adjacent pixel-format constructors.
