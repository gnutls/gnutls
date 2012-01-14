eval '(exit $?0)' && eval 'exec perl -wS "$0" ${1+"$@"}'
  & eval 'exec perl -wS "$0" $argv:q'
    if 0;

$dir = shift;
$param2 = shift;

if ($param2 ne '') {
  $enum = 1;
} else {
  $enum = 0;
}

sub key_of_record {
  local($record) = @_;

  # Split record into lines:
  my @lines = split /\n/, $record;

  my ($i) = 1;
  my ($key) = $lines[$i]; 

  if ($enum == 1) {
    while( !($key =~ m/\@c\s(.*)\n/) && ($i < 5)) { $i=$i+1; $key = $lines[$i]; }
  } else {
    while( !($key =~ m/^\\functionTitle\{(.*)\}/) && ($i < 5)) { $i=$i+1; $key = $lines[$i]; }
  }

  return $key;
}

if ($enum == 1) {
  $/="\@end table";          # Records are separated by blank lines.
} else {
  $/="\n\\end{function}";          # Records are separated by blank lines.
}
@records = <>;  # Read in whole file, one record per array element.

$/="\n";

mkdir $dir;

if ($enum == 0) {
  @records = sort { key_of_record($a) cmp key_of_record($b) } @records;
}

foreach (@records) {
  $key = $_;
  if ($enum == 1) {
    $key =~ m/\@c\s(.*)\n/;
    $key = $1;
  } else {
    $key =~ m/\\functionTitle\{(.*)\}/;
    $key = $1;
  }

  if (defined $key && $key ne "") {
    open FILE, "> $dir/$key\n" or die $!;
    print FILE $_ . "\n";
    close FILE;
  }
} 

#print @records;
