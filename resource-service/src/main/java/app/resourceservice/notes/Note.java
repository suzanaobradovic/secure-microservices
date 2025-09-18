package app.resourceservice.notes;

import lombok.AllArgsConstructor;
import lombok.Data;

// Simple data model representing a single note created by a user in the Resource Service.
@Data
@AllArgsConstructor
public class Note {
  String id;
  String owner;
  String title;
  String content;
}
