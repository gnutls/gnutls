#!/usr/bin/perl

$dir = shift;

sub key_of_record {
  local($record) = @_;

  # Split record into lines:
  my @lines = split /\n/, $record;

  my ($i) = 1;
  my ($key) = $lines[$i]; 

  while( !($key =~ m/^\\functionTitle\{(.*)\}/) && ($i < 5)) { $i=$i+1; $key = $lines[$i]; }

  return $key;
}

$/="\n\\end{function}";          # Records are separated by blank lines.
@records = <>;  # Read in whole file, one record per array element.

mkdir $dir;

@records = sort { key_of_record($a) cmp key_of_record($b) } @records;
foreach (@records) {
  $key = $_;
  $key =~  m/\\functionTitle\{(.*)\}/;

  $key = $1;
  $key =~ s/\\_/_/g;

  if (defined $key && $key ne "") {
    open FILE, "> $dir/$key\n" or die $!;
    print FILE $_ . "\n";
    close FILE;
  }
} 

#print @records;
