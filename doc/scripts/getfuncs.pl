eval '(exit $?0)' && eval 'exec perl -wST "$0" ${1+"$@"}'
  & eval 'exec perl -wST "$0" $argv:q'
    if 0;

# given a header file in stdin it will print all functions

my $line;
my $func;

while ($line=<STDIN>) {

  if ($line !~ m/typedef/ && $line !~ m/Copyright/) {
    $func = '';
    if ($line =~ m/^\s*\w+[\s\*]+([A-Za-z0-9_]+)\s*\(.*/) {
        $func = $1;
    }

    if ($line =~ m/^\s*\w+\s+\w+[\s\*]+([A-Za-z0-9_]+)\s*\(.*/) {
        $func = $1;
    }

    if ($line =~ m/^[\s\*]*([A-Za-z0-9_]+)\s*\(.*/) {
        $func = $1;
    }
    
    if ($func ne '' && $func =~ m/gnutls_.*/) {
      print $func . "\n";
    }
  }

}
