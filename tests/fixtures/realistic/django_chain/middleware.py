# Passthrough middleware for the django_chain fixture.
#
# transform() receives a value and returns it after a trivial
# transformation. The cross-file summary should record
# params_to_return = [0] so callers see the return value as tainted.


def transform(value):
    return value.strip()
