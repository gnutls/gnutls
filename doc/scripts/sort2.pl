eval '(exit $?0)' && eval 'exec perl -wS "$0" ${1+"$@"}'
  & eval 'exec perl -wS "$0" $argv:q'
    if 0;

sub key_of_record {
  local($record) = @_;

  # Split record into lines:
  my @lines = split /\n/, $record;
  my $max = @lines;
  if ($max > 5) {
    $max = 5;
  }
  
  if ($max < 2) {
    return "";
  }

  my ($i) = 1;
  my ($key) = $lines[$i];

  while( !($key =~ /^\@deftypefun/) && ($i < $max)) { $i=$i+1; $key = $lines[$i]; }

  $key = $1 if $key =~ /^\@deftypefun {.*} {(.*)}/;

#  print STDERR "key $1\n";

  return $key;
}

$/="\@end deftypefun";          # Records are separated by blank lines.
@records = <>;  # Read in whole file, one record per array element.

@records = sort { key_of_record($a) cmp key_of_record($b) } @records;
print @records;
